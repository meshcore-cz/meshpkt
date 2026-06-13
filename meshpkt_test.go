package meshpkt

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"testing"
	"time"
)

// ── envelope ─────────────────────────────────────────────────────────────────

func TestEncodeDecodePacket_Flood(t *testing.T) {
	want := Packet{
		Route:        RouteFlood,
		Type:         PayloadGrpTxt,
		Version:      0,
		PathHashSize: 2,
		Payload:      []byte{0x01, 0x02, 0x03},
	}
	raw, err := EncodePacket(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodePacket(raw)
	if err != nil {
		t.Fatal(err)
	}
	checkPacket(t, got, want)
}

func TestEncodeDecodePacket_WithPath(t *testing.T) {
	// 3 hops × 2-byte hashes
	want := Packet{
		Route:        RouteFlood,
		Type:         PayloadTxtMsg,
		Version:      0,
		PathHashSize: 2,
		Path:         []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
		Payload:      []byte{0x42},
	}
	raw, err := EncodePacket(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodePacket(raw)
	if err != nil {
		t.Fatal(err)
	}
	checkPacket(t, got, want)
	if got.HopCount() != 3 {
		t.Fatalf("HopCount = %d, want 3", got.HopCount())
	}
	hops := got.Hops()
	if len(hops) != 3 {
		t.Fatalf("len(Hops) = %d, want 3", len(hops))
	}
	if !bytes.Equal(hops[0], []byte{0xAA, 0xBB}) {
		t.Fatalf("hops[0] = %x, want aabb", hops[0])
	}
}

func TestEncodeDecodePacket_TransportCodes(t *testing.T) {
	// Transport codes with version 0 (strict).
	want := Packet{
		Route:          RouteTransportFlood,
		Type:           PayloadAdvert,
		Version:        0,
		TransportCodes: [2]uint16{0x1234, 0x5678},
		PathHashSize:   1,
		Payload:        []byte{0xFF},
	}
	raw, err := EncodePacket(want)
	if err != nil {
		t.Fatal(err)
	}
	// header(1) + transport_codes(4) + path_len(1) + payload(1) = 7
	if len(raw) != 7 {
		t.Fatalf("encoded length = %d, want 7", len(raw))
	}
	got, err := DecodePacket(raw)
	if err != nil {
		t.Fatal(err)
	}
	checkPacket(t, got, want)
	if got.TransportCodes != want.TransportCodes {
		t.Fatalf("TransportCodes = %v, want %v", got.TransportCodes, want.TransportCodes)
	}
}

func TestDecodePacket_TooShort(t *testing.T) {
	if _, err := DecodePacket([]byte{0x15}); err == nil {
		t.Fatal("expected error for 1-byte input")
	}
}

// ── M1 strict frame validation ───────────────────────────────────────────────

func TestDecodeRejectsReservedPathMode(t *testing.T) {
	// Manually craft a packet with path mode 0b11 (PathHashSize encoded as reserved).
	// Header: version=0, type=ADVERT(4), route=FLOOD(1) → (4<<2)|1 = 0x11
	// path_len byte: top 2 bits = 0b11 (reserved), hop count = 0.
	raw := []byte{
		(byte(PayloadAdvert) << 2) | byte(RouteFlood), // header: 0x11
		0xC0, // path_len: 0b11000000 = mode 3 (reserved), 0 hops
	}
	if _, err := DecodePacket(raw); err == nil {
		t.Fatal("expected ErrInvalidPathHashSize for reserved path mode 0b11")
	}
}

func TestEncodeRejectsFourBytePathHashes(t *testing.T) {
	p := Packet{
		Route:        RouteFlood,
		Type:         PayloadAdvert,
		PathHashSize: 4, // reserved
		Payload:      []byte{0x01},
	}
	if _, err := EncodePacket(p); err == nil {
		t.Fatal("expected error for PathHashSize=4")
	}
}

func TestEncodeRejectsUnalignedPath(t *testing.T) {
	p := Packet{
		Route:        RouteFlood,
		Type:         PayloadAdvert,
		PathHashSize: 2,
		Path:         []byte{0xAA, 0xBB, 0xCC}, // 3 bytes, not aligned to 2
		Payload:      []byte{0x01},
	}
	if _, err := EncodePacket(p); err == nil {
		t.Fatal("expected ErrUnalignedPath")
	}
}

func TestEncodeRejectsPathOver64Bytes(t *testing.T) {
	p := Packet{
		Route:        RouteFlood,
		Type:         PayloadAdvert,
		PathHashSize: 2,
		Path:         make([]byte, 66), // 33 hops × 2 = 66 > 64
		Payload:      []byte{0x01},
	}
	if _, err := EncodePacket(p); err == nil {
		t.Fatal("expected ErrPathTooLong")
	}
}

func TestEncodeRejectsPayloadOver184Bytes(t *testing.T) {
	p := Packet{
		Route:        RouteFlood,
		Type:         PayloadAdvert,
		PathHashSize: 2,
		Payload:      make([]byte, 185),
	}
	if _, err := EncodePacket(p); err == nil {
		t.Fatal("expected ErrPayloadTooLong")
	}
}

func TestEncodeRejectsUnsupportedVersion(t *testing.T) {
	p := Packet{
		Route:        RouteFlood,
		Type:         PayloadAdvert,
		Version:      1,
		PathHashSize: 2,
		Payload:      []byte{0x01},
	}
	if _, err := EncodePacket(p); err == nil {
		t.Fatal("expected ErrUnsupportedVersion for version=1")
	}
}

func TestDecodeRejectsTruncatedTransportCodes(t *testing.T) {
	// Transport route but only 2 bytes for transport codes (need 4).
	raw := []byte{
		byte(RouteTransportFlood), // header: route=TRANSPORT_FLOOD
		0x12, 0x34,                // partial transport codes (need 4 bytes)
	}
	if _, err := DecodePacket(raw); err == nil {
		t.Fatal("expected error for truncated transport codes")
	}
}

func TestDecodeRejectsTruncatedPath(t *testing.T) {
	// path_len says 3 hops × 2 bytes = 6 bytes, but payload has only 2.
	raw := []byte{
		byte(PayloadAdvert) << 2, // header
		byte(0x01<<6) | 3,        // path_len: hash_size=2(01), hops=3
		0xAA, 0xBB,               // only 2 bytes, need 6
	}
	if _, err := DecodePacket(raw); err == nil {
		t.Fatal("expected error for truncated path")
	}
}

func TestRoundTripAllRouteModes(t *testing.T) {
	for _, route := range AllRouteTypes {
		p := Packet{
			Route:        route,
			Type:         PayloadAdvert,
			Version:      0,
			PathHashSize: 2,
			Payload:      []byte{0x42},
		}
		if route.IsTransport() {
			p.TransportCodes = [2]uint16{0x1111, 0x2222}
		}
		raw, err := EncodePacket(p)
		if err != nil {
			t.Fatalf("route=%s: encode: %v", route, err)
		}
		got, err := DecodePacket(raw)
		if err != nil {
			t.Fatalf("route=%s: decode: %v", route, err)
		}
		if got.Route != route {
			t.Errorf("route=%s: got %s", route, got.Route)
		}
	}
}

func TestRoundTripPathHashSizesOneTwoThree(t *testing.T) {
	for _, size := range []int{1, 2, 3} {
		p := Packet{
			Route:        RouteFlood,
			Type:         PayloadAdvert,
			Version:      0,
			PathHashSize: size,
			Path:         make([]byte, size*3), // 3 hops
			Payload:      []byte{0x42},
		}
		raw, err := EncodePacket(p)
		if err != nil {
			t.Fatalf("pathHashSize=%d: encode: %v", size, err)
		}
		got, err := DecodePacket(raw)
		if err != nil {
			t.Fatalf("pathHashSize=%d: decode: %v", size, err)
		}
		if got.PathHashSize != size {
			t.Errorf("pathHashSize=%d: got %d", size, got.PathHashSize)
		}
		if got.HopCount() != 3 {
			t.Errorf("pathHashSize=%d: HopCount = %d, want 3", size, got.HopCount())
		}
	}
}

func TestEncodeRejectsTooManyHops(t *testing.T) {
	size := 1
	p := Packet{
		Route:        RouteFlood,
		Type:         PayloadAdvert,
		PathHashSize: size,
		Path:         make([]byte, 64), // 64 hops × 1 = 64 bytes, but MaxHopCount=63
		Payload:      []byte{0x01},
	}
	if _, err := EncodePacket(p); err == nil {
		t.Fatal("expected ErrTooManyHops for 64 1-byte hops")
	}
}

func TestEncodeMaxValidPath(t *testing.T) {
	// 32 hops × 2 bytes = 64 bytes ≤ MaxPathBytes, 31 hops × 2 bytes = 62 ≤ 64.
	size := 2
	p := Packet{
		Route:        RouteFlood,
		Type:         PayloadAdvert,
		PathHashSize: size,
		Path:         make([]byte, 62), // 31 hops
		Payload:      []byte{0x01},
	}
	if _, err := EncodePacket(p); err != nil {
		t.Fatalf("unexpected error for 31-hop 2-byte path: %v", err)
	}
}

func checkPacket(t *testing.T, got, want Packet) {
	t.Helper()
	if got.Route != want.Route {
		t.Errorf("Route = %v, want %v", got.Route, want.Route)
	}
	if got.Type != want.Type {
		t.Errorf("Type = %v, want %v", got.Type, want.Type)
	}
	if got.Version != want.Version {
		t.Errorf("Version = %d, want %d", got.Version, want.Version)
	}
	if got.PathHashSize != want.PathHashSize {
		t.Errorf("PathHashSize = %d, want %d", got.PathHashSize, want.PathHashSize)
	}
	if !bytes.Equal(got.Path, want.Path) {
		t.Errorf("Path = %x, want %x", got.Path, want.Path)
	}
	if !bytes.Equal(got.Payload, want.Payload) {
		t.Errorf("Payload = %x, want %x", got.Payload, want.Payload)
	}
}

// ── channel helpers ───────────────────────────────────────────────────────────

func TestDeriveChannelSecret(t *testing.T) {
	secret := DeriveChannelSecret("#test")
	if len(secret) != ChannelSecretLen {
		t.Fatalf("secret length = %d, want %d", len(secret), ChannelSecretLen)
	}
	if !bytes.Equal(secret, DeriveChannelSecret("#test")) {
		t.Fatal("DeriveChannelSecret is not deterministic")
	}
}

func TestChannelHash(t *testing.T) {
	secret := DeriveChannelSecret("general")
	h := ChannelHash(secret)
	want := sha256.Sum256(secret[:16])
	if h != want[0] {
		t.Fatalf("ChannelHash = %02x, want %02x", h, want[0])
	}
}

// ── GRP_TXT round-trip ────────────────────────────────────────────────────────

func TestGroupTextPacket_RoundTrip(t *testing.T) {
	secret := DeriveChannelSecret("general")
	ts := time.Unix(1700000000, 0)

	raw, err := GroupTextPacket(secret, "Alice", "hello meshcore", ts)
	if err != nil {
		t.Fatal(err)
	}
	pkt, err := DecodePacket(raw)
	if err != nil {
		t.Fatal(err)
	}
	if pkt.Type != PayloadGrpTxt {
		t.Fatalf("Type = %v, want GRP_TXT", pkt.Type)
	}
	if pkt.Route != RouteFlood {
		t.Fatalf("Route = %v, want flood", pkt.Route)
	}
	if pkt.PathHashSize != 2 {
		t.Fatalf("PathHashSize = %d, want 2 (default)", pkt.PathHashSize)
	}

	gt, err := DecodeGroupTextPayload(secret, pkt.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if gt.Sender != "Alice" {
		t.Errorf("Sender = %q, want %q", gt.Sender, "Alice")
	}
	if gt.Text != "hello meshcore" {
		t.Errorf("Text = %q, want %q", gt.Text, "hello meshcore")
	}
	if gt.Timestamp.Unix() != ts.Unix() {
		t.Errorf("Timestamp = %v, want %v", gt.Timestamp, ts)
	}
	if gt.TxtType != 0 {
		t.Errorf("TxtType = %d, want 0", gt.TxtType)
	}
}

func TestGroupTextPacket_WrongSecret(t *testing.T) {
	secret := DeriveChannelSecret("#right")
	wrong := DeriveChannelSecret("#wrong")
	raw, err := GroupTextPacket(secret, "Bob", "test", time.Unix(1700000000, 0))
	if err != nil {
		t.Fatal(err)
	}
	pkt, _ := DecodePacket(raw)
	if _, err := DecodeGroupTextPayload(wrong, pkt.Payload); err == nil {
		t.Fatal("expected error decoding with wrong secret")
	}
}

func TestGroupTextPacket_PathHashSize1(t *testing.T) {
	secret := DeriveChannelSecret("general")
	raw, err := GroupTextPacket(secret, "Alice", "hello", time.Unix(1700000000, 0), WithPathHashSize(1))
	if err != nil {
		t.Fatal(err)
	}
	pkt, err := DecodePacket(raw)
	if err != nil {
		t.Fatal(err)
	}
	if pkt.PathHashSize != 1 {
		t.Fatalf("PathHashSize = %d, want 1", pkt.PathHashSize)
	}
	// path_len byte: bits7-6=00 (1-byte hashes), bits5-0=0 (0 hops) → 0x00
	if raw[1] != 0x00 {
		t.Fatalf("path_len = %02x, want 0x00", raw[1])
	}
	// channel_hash in payload is always 1 byte
	if pkt.Payload[0] != ChannelHash(secret) {
		t.Fatalf("channel_hash = %02x, want %02x", pkt.Payload[0], ChannelHash(secret))
	}
}

// ── TXT_MSG round-trip ────────────────────────────────────────────────────────

func TestDirectTextPacket_RoundTrip(t *testing.T) {
	shared, _ := hex.DecodeString("0102030405060708090a0b0c0d0e0f10")
	ts := time.Unix(1700000000, 0)
	destHash := byte(0xAB)
	srcHash := byte(0xCD)

	raw, err := DirectTextPacket(shared, destHash, srcHash, "direct hello", ts, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	pkt, err := DecodePacket(raw)
	if err != nil {
		t.Fatal(err)
	}
	if pkt.Type != PayloadTxtMsg {
		t.Fatalf("Type = %v, want TXT_MSG", pkt.Type)
	}

	dt, err := DecodeDirectTextPayload(shared, pkt.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if dt.DestHash != destHash {
		t.Errorf("DestHash = %02x, want %02x", dt.DestHash, destHash)
	}
	if dt.SrcHash != srcHash {
		t.Errorf("SrcHash = %02x, want %02x", dt.SrcHash, srcHash)
	}
	if dt.Text != "direct hello" {
		t.Errorf("Text = %q, want %q", dt.Text, "direct hello")
	}
	if dt.Timestamp.Unix() != ts.Unix() {
		t.Errorf("Timestamp = %d, want %d", dt.Timestamp.Unix(), ts.Unix())
	}
}

func TestDirectTextPacket_WrongSecret(t *testing.T) {
	shared, _ := hex.DecodeString("0102030405060708090a0b0c0d0e0f10")
	wrong, _ := hex.DecodeString("ffffffffffffffffffffffffffffffff")

	raw, _ := DirectTextPacket(shared, 0xAB, 0xCD, "test", time.Unix(1700000000, 0), 0, 0)
	pkt, _ := DecodePacket(raw)
	if _, err := DecodeDirectTextPayload(wrong, pkt.Payload); err == nil {
		t.Fatal("expected error decoding with wrong shared secret")
	}
}

// ── ADVERT decode ─────────────────────────────────────────────────────────────

func TestDecodeAdvertPayload(t *testing.T) {
	// Build a minimal ADVERT payload with a zero signature (unsigned).
	payload := make([]byte, 100) // pubkey(32) + ts(4) + sig(64) — all zeros
	for i := 0; i < 32; i++ {
		payload[i] = 0x42 // pubkey
	}
	binary.LittleEndian.PutUint32(payload[32:], 1700000000)
	// signature bytes (36–99) left as zeros → unsigned, skips verification

	// Appdata: flags=0x81 (chat node, has name), then name bytes.
	// Bit 7 (0x80) = has_name; lower nibble 0x01 = chat node type.
	payload = append(payload, 0x81)
	payload = append(payload, "TestNode"...)

	adv, err := DecodeAdvertPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(adv.PublicKey) != 32 || adv.PublicKey[0] != 0x42 {
		t.Errorf("PublicKey[0] = %02x, want 0x42", adv.PublicKey[0])
	}
	if adv.Timestamp.Unix() != 1700000000 {
		t.Errorf("Timestamp = %v", adv.Timestamp)
	}
	if adv.Name != "TestNode" {
		t.Errorf("Name = %q, want TestNode", adv.Name)
	}
	if adv.HasGPS {
		t.Error("HasGPS should be false when 0x10 flag not set")
	}
	if adv.NodeType != AdvertNodeChat {
		t.Errorf("NodeType = %d, want %d (chat)", adv.NodeType, AdvertNodeChat)
	}
}

func TestDecodeAdvertPayload_TooShort(t *testing.T) {
	if _, err := DecodeAdvertPayload(make([]byte, 50)); err == nil {
		t.Fatal("expected error for payload shorter than 100 bytes")
	}
}

// ── ADVERT signature ──────────────────────────────────────────────────────────

func TestSignAndVerifyAdvert(t *testing.T) {
	id, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}

	adv := Advert{
		PublicKey: id.PublicKey[:],
		NodeType:  AdvertNodeChat,
		Name:      "TestNode",
		HasGPS:    true,
		Lat:       50.0876,
		Lon:       14.4208,
	}

	payload, err := EncodeAdvertPayload(adv)
	if err != nil {
		t.Fatal(err)
	}

	// Before signing, signature is all zeros — decode should succeed (unsigned).
	if _, err := DecodeAdvertPayload(payload); err != nil {
		t.Fatalf("unsigned decode: %v", err)
	}

	// Sign with 64-byte private key.
	signed, err := SignAdvertPayload(payload, id.PrivateKey[:])
	if err != nil {
		t.Fatal(err)
	}

	// Decode should succeed and verify the signature.
	got, err := DecodeAdvertPayload(signed)
	if err != nil {
		t.Fatalf("signed decode: %v", err)
	}
	if got.Name != "TestNode" {
		t.Errorf("Name = %q, want TestNode", got.Name)
	}
	if !got.HasGPS {
		t.Error("HasGPS should be true")
	}
	if allZero(got.Signature) {
		t.Error("Signature should be non-zero after signing")
	}

	// VerifyAdvertSignature should also return true.
	if !VerifyAdvertSignature(signed) {
		t.Error("VerifyAdvertSignature returned false for a valid signature")
	}
}

func TestSignAdvert_FromSeed(t *testing.T) {
	id, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}

	// Restore identity from seed and sign.
	id2, err := IdentityFromSeed(id.Seed)
	if err != nil {
		t.Fatal(err)
	}

	adv := Advert{PublicKey: id2.PublicKey[:], Name: "SeedTest"}
	payload, _ := EncodeAdvertPayload(adv)
	signed, err := SignAdvertPayload(payload, id2.Seed[:]) // 32-byte seed path
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeAdvertPayload(signed); err != nil {
		t.Fatalf("seed-signed decode: %v", err)
	}
}

func TestSignAdvert_WrongKey(t *testing.T) {
	id, _ := GenerateIdentity()
	other, _ := GenerateIdentity()

	adv := Advert{PublicKey: id.PublicKey[:], Name: "WrongKey"}
	payload, _ := EncodeAdvertPayload(adv)

	_, err := SignAdvertPayload(payload, other.PrivateKey[:])
	if err == nil {
		t.Fatal("expected error when signing with wrong key")
	}
}

func TestDecodeAdvert_BadSignature(t *testing.T) {
	id, _ := GenerateIdentity()

	adv := Advert{PublicKey: id.PublicKey[:], Name: "BadSig"}
	payload, _ := EncodeAdvertPayload(adv)
	signed, _ := SignAdvertPayload(payload, id.PrivateKey[:])

	// Tamper with the name in appdata (byte 101 is the flags, 102+ is the name).
	tampered := make([]byte, len(signed))
	copy(tampered, signed)
	tampered[len(tampered)-1] ^= 0xFF // flip last byte of name

	if _, err := DecodeAdvertPayload(tampered); err == nil {
		t.Fatal("expected signature verification error after tampering")
	}
}

func TestVerifyAdvertSignature_Unsigned(t *testing.T) {
	// All-zero signature should return true (unsigned packet is not invalid).
	payload := make([]byte, 105)
	if !VerifyAdvertSignature(payload) {
		t.Error("unsigned (zero sig) payload should return true from VerifyAdvertSignature")
	}
}

func TestVerifyAdvertSignature_TooShort(t *testing.T) {
	if VerifyAdvertSignature(make([]byte, 50)) {
		t.Error("too-short payload should return false from VerifyAdvertSignature")
	}
}

// ── ADVERT SignAdvert / VerifyAdvert ──────────────────────────────────────────

func TestSignAdvert_AndVerifyAdvert(t *testing.T) {
	id, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	adv := Advert{
		PublicKey: id.PublicKey[:],
		NodeType:  AdvertNodeRepeater,
		Name:      "TestRepeater",
		HasGPS:    true,
		Lat:       50.08,
		Lon:       14.42,
	}

	signed, err := SignAdvert(id, adv)
	if err != nil {
		t.Fatal(err)
	}
	if len(signed.Signature) != 64 || allZero(signed.Signature) {
		t.Error("Signature should be 64 non-zero bytes after SignAdvert")
	}
	if err := VerifyAdvert(signed); err != nil {
		t.Errorf("VerifyAdvert returned error: %v", err)
	}
}

func TestSignAdvert_WrongIdentity(t *testing.T) {
	id1, _ := GenerateIdentity()
	id2, _ := GenerateIdentity()
	adv := Advert{PublicKey: id1.PublicKey[:], Name: "test"}
	if _, err := SignAdvert(id2, adv); err == nil {
		t.Fatal("expected error when signing with wrong identity")
	}
}

// ── ADVERT strict decoder ─────────────────────────────────────────────────────

func TestDecodeAdvertPayloadStrict_MissingGPS(t *testing.T) {
	// Flags claim GPS (0x10) but no GPS bytes follow.
	payload := make([]byte, 101)
	payload[100] = 0x10 // has_gps flag, but no GPS bytes
	if _, err := DecodeAdvertPayloadStrict(payload); err == nil {
		t.Fatal("expected error for missing GPS bytes in strict mode")
	}
}

func TestDecodeAdvertPayloadStrict_BadLatitude(t *testing.T) {
	payload := make([]byte, 109) // 100 + flags(1) + lat(4) + lon(4)
	payload[100] = 0x10          // has_gps
	// lat = 95_000_000 × 1e-6 = 95.0° — out of range
	binary.LittleEndian.PutUint32(payload[101:], uint32(int32(95_000_000)))
	binary.LittleEndian.PutUint32(payload[105:], 0)
	if _, err := DecodeAdvertPayloadStrict(payload); err == nil {
		t.Fatal("expected error for latitude 95° in strict mode")
	}
}

func TestDecodeAdvertPayloadStrict_ValidRoundTrip(t *testing.T) {
	id, _ := GenerateIdentity()
	adv := Advert{
		PublicKey: id.PublicKey[:],
		NodeType:  AdvertNodeChat,
		Name:      "StrictTest",
		HasGPS:    true,
		Lat:       48.8566,
		Lon:       2.3522,
	}
	payload, _ := EncodeAdvertPayload(adv)
	got, err := DecodeAdvertPayloadStrict(payload)
	if err != nil {
		t.Fatalf("strict decode failed: %v", err)
	}
	if got.Name != "StrictTest" {
		t.Errorf("Name = %q, want StrictTest", got.Name)
	}
	if !got.HasGPS {
		t.Error("HasGPS should be true")
	}
}

// ── ADVERT Feature1/Feature2 ──────────────────────────────────────────────────

func TestAdvertFeatureFields_RoundTrip(t *testing.T) {
	id, _ := GenerateIdentity()
	adv := Advert{
		PublicKey: id.PublicKey[:],
		NodeType:  AdvertNodeSensor,
		HasFeat1:  true,
		Feature1:  0xABCD,
		HasFeat2:  true,
		Feature2:  0x1234,
		Name:      "SensorNode",
	}
	payload, err := EncodeAdvertPayload(adv)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeAdvertPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	if !got.HasFeat1 || got.Feature1 != 0xABCD {
		t.Errorf("Feature1 = %04x, want ABCD", got.Feature1)
	}
	if !got.HasFeat2 || got.Feature2 != 0x1234 {
		t.Errorf("Feature2 = %04x, want 1234", got.Feature2)
	}
}

// ── Identity ECDH ─────────────────────────────────────────────────────────────

func TestIdentity_SharedSecret_Symmetric(t *testing.T) {
	alice, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	bob, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}

	ss1, err := alice.SharedSecret(bob.PublicKey)
	if err != nil {
		t.Fatalf("alice.SharedSecret: %v", err)
	}
	ss2, err := bob.SharedSecret(alice.PublicKey)
	if err != nil {
		t.Fatalf("bob.SharedSecret: %v", err)
	}
	if ss1 != ss2 {
		t.Errorf("shared secrets differ:\nalice→bob: %x\nbob→alice: %x", ss1, ss2)
	}
	// Shared secret should not be all zeros.
	var zero [32]byte
	if ss1 == zero {
		t.Error("shared secret is all zeros")
	}
}

func TestIdentity_SharedSecret_Deterministic(t *testing.T) {
	alice, _ := GenerateIdentity()
	bob, _ := GenerateIdentity()

	ss1, err := alice.SharedSecret(bob.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	ss2, err := alice.SharedSecret(bob.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if ss1 != ss2 {
		t.Error("SharedSecret is not deterministic")
	}
}

func TestIdentity_Sign_Verify(t *testing.T) {
	id, _ := GenerateIdentity()
	msg := []byte("hello meshcore")
	sig := id.Sign(msg)

	if !Verify(id.PublicKey, msg, sig) {
		t.Error("Verify returned false for valid signature")
	}
	// Tamper with message.
	if Verify(id.PublicKey, []byte("hello meshcorE"), sig) {
		t.Error("Verify should return false for tampered message")
	}
}

func TestIdentityFromSeed_RoundTrip(t *testing.T) {
	id1, _ := GenerateIdentity()
	id2, err := IdentityFromSeed(id1.Seed)
	if err != nil {
		t.Fatal(err)
	}
	if id1.PublicKey != id2.PublicKey {
		t.Error("PublicKey differs after restore from seed")
	}
	if id1.PrivateKey != id2.PrivateKey {
		t.Error("PrivateKey differs after restore from seed")
	}
}

// ── TRACE ─────────────────────────────────────────────────────────────────────

func TestTracePacket_RoundTrip(t *testing.T) {
	// Two 1-byte route hashes, flags=0 (hash width = 1 byte).
	routeHashes := []byte{0xA1, 0xB2}
	raw, err := TracePacket(0xDEADBEEF, 0xCAFEBABE, 0x00, routeHashes)
	if err != nil {
		t.Fatal(err)
	}

	pkt, err := DecodePacket(raw)
	if err != nil {
		t.Fatal(err)
	}
	if pkt.Type != PayloadTrace {
		t.Fatalf("Type = %v, want TRACE", pkt.Type)
	}
	if pkt.Route != RouteDirect {
		t.Fatalf("Route = %v, want DIRECT", pkt.Route)
	}
	// New trace: no SNRs yet.
	if len(pkt.Path) != 0 {
		t.Fatalf("Path len = %d, want 0 for new trace", len(pkt.Path))
	}

	tr, err := DecodeTracePayload(pkt.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if tr.Tag != 0xDEADBEEF {
		t.Errorf("Tag = %08x, want deadbeef", tr.Tag)
	}
	if tr.AuthCode != 0xCAFEBABE {
		t.Errorf("AuthCode = %08x, want cafebabe", tr.AuthCode)
	}
	if tr.HashWidth() != 1 {
		t.Errorf("HashWidth = %d, want 1", tr.HashWidth())
	}
	hashes := tr.RouteHashes()
	if len(hashes) != 2 || hashes[0][0] != 0xA1 || hashes[1][0] != 0xB2 {
		t.Errorf("RouteHashes = %v, want [{a1} {b2}]", hashes)
	}
}

func TestTraceSNRs(t *testing.T) {
	// From the spec examples: 0x1D = +7.25 dB, 0xF4 = -3.00 dB.
	snrs := TraceSNRs([]byte{0x1D, 0xF4})
	if len(snrs) != 2 {
		t.Fatalf("len = %d, want 2", len(snrs))
	}
	if snrs[0] != 7.25 {
		t.Errorf("snrs[0] = %.2f, want 7.25", snrs[0])
	}
	if snrs[1] != -3.00 {
		t.Errorf("snrs[1] = %.2f, want -3.00", snrs[1])
	}
}

func TestTracePayload_TooShort(t *testing.T) {
	if _, err := DecodeTracePayload(make([]byte, 8)); err == nil {
		t.Fatal("expected error for payload shorter than 9 bytes")
	}
}

func TestTracePayload_HashWidth(t *testing.T) {
	cases := []struct{ flags, want byte }{
		{0x00, 1}, {0x01, 2}, {0x02, 4}, {0x03, 8},
	}
	for _, c := range cases {
		tr := TracePayload{Flags: c.flags}
		if got := tr.HashWidth(); got != int(c.want) {
			t.Errorf("flags=%02x: HashWidth = %d, want %d", c.flags, got, c.want)
		}
	}
}

// ── TXT_MSG ACK ───────────────────────────────────────────────────────────────

func TestTextAckCRC(t *testing.T) {
	// Mirrors MeshCore firmware BaseChatMesh::composeMsgPacket:
	//   sha256( timestamp[4 LE] | (attempt&3) | text | senderPubKey[32] )[0:4] as LE uint32.
	ts := uint32(1700000000)
	attempt := byte(0)
	text := "direct hello"
	pub := make([]byte, 32)
	for i := range pub {
		pub[i] = byte(i)
	}

	// Independent reference computation.
	temp := make([]byte, 0, 5+len(text))
	var tsb [4]byte
	binary.LittleEndian.PutUint32(tsb[:], ts)
	temp = append(temp, tsb[:]...)
	temp = append(temp, attempt&0x03)
	temp = append(temp, text...)
	h := sha256.Sum256(append(append([]byte{}, temp...), pub...))
	want := binary.LittleEndian.Uint32(h[:4])

	if got := TextAckCRC(ts, attempt, text, pub); got != want {
		t.Fatalf("TextAckCRC = %08x, want %08x", got, want)
	}

	// Only the low 2 bits of attempt are part of the CRC.
	if TextAckCRC(ts, 0, text, pub) != TextAckCRC(ts, 0x04, text, pub) {
		t.Errorf("attempt high bits must not affect the CRC")
	}

	// TextAckPacket round-trips the CRC through a real ACK packet.
	raw, err := TextAckPacket(ts, attempt, text, pub)
	if err != nil {
		t.Fatal(err)
	}
	pkt, err := DecodePacket(raw)
	if err != nil {
		t.Fatal(err)
	}
	if pkt.Type != PayloadAck {
		t.Fatalf("Type = %v, want ACK", pkt.Type)
	}
	if pkt.Route != RouteFlood {
		t.Fatalf("Route = %v, want FLOOD", pkt.Route)
	}
	gotCRC, err := DecodeAckPayload(pkt.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if gotCRC != want {
		t.Errorf("ACK packet CRC = %08x, want %08x", gotCRC, want)
	}

	if _, err := TextAckPacket(ts, attempt, text, pub[:31]); err == nil {
		t.Errorf("expected error for short sender public key")
	}
}

func TestDirectTextPacketFromIdentity(t *testing.T) {
	var ss, rs [32]byte
	for i := 0; i < 32; i++ {
		ss[i] = byte(i)
		rs[i] = byte(0x20 + i)
	}
	sender, _ := IdentityFromSeed(ss)
	recip, _ := IdentityFromSeed(rs)

	raw, err := DirectTextPacketFromIdentity(ss, recip.PublicKey, "bridged dm test", time.Unix(1700000000, 0), 0)
	if err != nil {
		t.Fatal(err)
	}
	pkt, err := DecodePacket(raw)
	if err != nil {
		t.Fatal(err)
	}
	if pkt.Type != PayloadTxtMsg || pkt.Route != RouteFlood {
		t.Fatalf("type=%v route=%v, want TXT_MSG/FLOOD", pkt.Type, pkt.Route)
	}
	if pkt.Payload[0] != recip.PublicKey[0] || pkt.Payload[1] != sender.PublicKey[0] {
		t.Fatalf("dest/src hash = %02x/%02x, want %02x/%02x",
			pkt.Payload[0], pkt.Payload[1], recip.PublicKey[0], sender.PublicKey[0])
	}

	// The recipient derives the same firmware-compatible shared secret and decrypts it.
	shared, err := recip.SharedSecret(sender.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	dt, err := DecodeDirectTextPayload(shared[:cipherKeySize], pkt.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if dt.Text != "bridged dm test" {
		t.Fatalf("text = %q, want %q", dt.Text, "bridged dm test")
	}
	if dt.Timestamp.Unix() != 1700000000 {
		t.Fatalf("ts = %d, want 1700000000", dt.Timestamp.Unix())
	}
}

// ── MULTIPART ─────────────────────────────────────────────────────────────────

func TestMultipartAckPacket_RoundTrip(t *testing.T) {
	const crc = uint32(0xABCD1234)
	const remaining = byte(2)

	raw, err := MultipartAckPacket(remaining, crc)
	if err != nil {
		t.Fatal(err)
	}

	pkt, err := DecodePacket(raw)
	if err != nil {
		t.Fatal(err)
	}
	if pkt.Type != PayloadMultipart {
		t.Fatalf("Type = %v, want MULTIPART", pkt.Type)
	}
	if pkt.Route != RouteDirect {
		t.Fatalf("Route = %v, want DIRECT", pkt.Route)
	}

	m, err := DecodeMultipartPayload(pkt.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if m.Remaining != remaining {
		t.Errorf("Remaining = %d, want %d", m.Remaining, remaining)
	}
	if m.InnerType != PayloadAck {
		t.Errorf("InnerType = %v, want ACK", m.InnerType)
	}

	gotCRC, err := DecodeAckPayload(m.InnerPayload)
	if err != nil {
		t.Fatal(err)
	}
	if gotCRC != crc {
		t.Errorf("CRC = %08x, want %08x", gotCRC, crc)
	}
}

func TestMultipartPayload_Descriptor(t *testing.T) {
	// descriptor = (remaining << 4) | inner_type
	// remaining=1, inner_type=ACK(0x03) → 0x13
	payload := []byte{0x13, 0xAA, 0xBB, 0xCC, 0xDD}
	m, err := DecodeMultipartPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	if m.Remaining != 1 {
		t.Errorf("Remaining = %d, want 1", m.Remaining)
	}
	if m.InnerType != PayloadAck {
		t.Errorf("InnerType = %v, want ACK", m.InnerType)
	}
	if len(m.InnerPayload) != 4 {
		t.Errorf("InnerPayload len = %d, want 4", len(m.InnerPayload))
	}
}

func TestMultipartPayload_TooShort(t *testing.T) {
	if _, err := DecodeMultipartPayload([]byte{}); err == nil {
		t.Fatal("expected error for empty payload")
	}
}
