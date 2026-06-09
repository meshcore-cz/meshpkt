package meshpkt

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"
)

// Advert holds the decoded content of an ADVERT (node advertisement) packet.
// ADVERT payloads are unencrypted.
//
// Wire layout: [pubkey:32][ts:4 LE][signature:64][appdata...]
//
// Appdata (all fields optional, controlled by flags byte):
//
//	[flags:1][lat?:4 int32 LE, ×1e-6°][lon?:4 int32 LE, ×1e-6°][feat1?:2 LE][feat2?:2 LE][name?:string]
//
// Flags lower nibble: node type (0=unknown, 1=chat, 2=repeater, 3=room, 4=sensor)
// Flags upper nibble: 0x10=has location, 0x20=has feature1, 0x40=has feature2, 0x80=has name
type Advert struct {
	PublicKey []byte    // 32-byte Ed25519 public key
	Timestamp time.Time // broadcast timestamp
	Signature []byte    // 64-byte Ed25519 signature (zero-padded if shorter)
	NodeType  byte      // 0=unknown, 1=chat, 2=repeater, 3=room, 4=sensor
	HasGPS    bool      // true when Lat/Lon are valid
	Lat, Lon  float64   // GPS coordinates in degrees (valid when HasGPS)
	Feature1  uint16    // optional feature flags 1 (present when 0x20 flag set)
	Feature2  uint16    // optional feature flags 2 (present when 0x40 flag set)
	HasFeat1  bool      // true when Feature1 was present in the payload
	HasFeat2  bool      // true when Feature2 was present in the payload
	Name      string    // node name (empty if not advertised)
}

// Sentinel errors for strict ADVERT decoding.
var (
	ErrAdvertTooShort      = errors.New("meshpkt: ADVERT payload too short (need at least 100 bytes)")
	ErrAdvertBadSignature  = errors.New("meshpkt: ADVERT signature verification failed")
	ErrAdvertMissingGPS    = errors.New("meshpkt: ADVERT flags declare GPS but bytes are missing")
	ErrAdvertMissingFeat1  = errors.New("meshpkt: ADVERT flags declare feature1 but bytes are missing")
	ErrAdvertMissingFeat2  = errors.New("meshpkt: ADVERT flags declare feature2 but bytes are missing")
	ErrAdvertLatOutOfRange = errors.New("meshpkt: ADVERT latitude out of range [-90, 90]")
	ErrAdvertLonOutOfRange = errors.New("meshpkt: ADVERT longitude out of range [-180, 180]")
)

// AdvertNodeType constants for Advert.NodeType.
const (
	AdvertNodeUnknown  byte = 0
	AdvertNodeChat     byte = 1
	AdvertNodeRepeater byte = 2
	AdvertNodeRoom     byte = 3
	AdvertNodeSensor   byte = 4
)

// EncodeAdvertPayload encodes an Advert to its wire payload bytes.
//
// adv.PublicKey must be exactly 32 bytes. Signature is zero-padded to 64 bytes
// if shorter. Lat/Lon are encoded as int32 LE (degrees × 1e6) when HasGPS is true.
func EncodeAdvertPayload(adv Advert) ([]byte, error) {
	if len(adv.PublicKey) != 32 {
		return nil, fmt.Errorf("meshpkt: ADVERT public key must be 32 bytes, got %d", len(adv.PublicKey))
	}

	ts := adv.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}

	// Fixed prefix: pubkey(32) + ts(4) + sig(64)
	buf := make([]byte, 0, 101+len(adv.Name))
	buf = append(buf, adv.PublicKey...)

	var tsBytes [4]byte
	binary.LittleEndian.PutUint32(tsBytes[:], uint32(ts.Unix()))
	buf = append(buf, tsBytes[:]...)

	var sig [64]byte
	copy(sig[:], adv.Signature)
	buf = append(buf, sig[:]...)

	// Appdata flags byte: lower nibble = node type, upper nibble = field presence.
	flags := adv.NodeType & 0x0F
	if adv.HasGPS {
		flags |= 0x10
	}
	if adv.HasFeat1 {
		flags |= 0x20
	}
	if adv.HasFeat2 {
		flags |= 0x40
	}
	if adv.Name != "" {
		flags |= 0x80
	}
	buf = append(buf, flags)

	// GPS coordinates as int32 LE (degrees × 1e6).
	if adv.HasGPS {
		var latBytes, lonBytes [4]byte
		binary.LittleEndian.PutUint32(latBytes[:], uint32(int32(math.Round(adv.Lat*1e6))))
		binary.LittleEndian.PutUint32(lonBytes[:], uint32(int32(math.Round(adv.Lon*1e6))))
		buf = append(buf, latBytes[:]...)
		buf = append(buf, lonBytes[:]...)
	}

	if adv.HasFeat1 {
		var f [2]byte
		binary.LittleEndian.PutUint16(f[:], adv.Feature1)
		buf = append(buf, f[:]...)
	}

	if adv.HasFeat2 {
		var f [2]byte
		binary.LittleEndian.PutUint16(f[:], adv.Feature2)
		buf = append(buf, f[:]...)
	}

	// Node name.
	if adv.Name != "" {
		buf = append(buf, []byte(adv.Name)...)
	}

	return buf, nil
}

// advertSignedMessage returns the bytes covered by the ADVERT Ed25519 signature:
// public_key (32) || timestamp (4) || app_data (everything after offset 100).
// This matches the firmware's signing order in Mesh.cpp.
func advertSignedMessage(payload []byte) []byte {
	appData := payload[100:]
	msg := make([]byte, 36+len(appData))
	copy(msg[:36], payload[:36])
	copy(msg[36:], appData)
	return msg
}

// allZero reports whether every byte in b is 0x00.
func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// VerifyAdvertSignature reports whether the ADVERT payload carries a valid
// Ed25519 signature over public_key || timestamp || app_data.
//
// Returns true for all-zero signatures — those are unsigned/synthetic packets
// (e.g. from the codec tool). Returns false for a payload shorter than 100
// bytes or for a non-zero signature that does not verify.
func VerifyAdvertSignature(payload []byte) bool {
	if len(payload) < 100 {
		return false
	}
	if allZero(payload[36:100]) {
		return true // unsigned packet — nothing to verify
	}
	return ed25519.Verify(
		ed25519.PublicKey(payload[0:32]),
		advertSignedMessage(payload),
		payload[36:100],
	)
}

// SignAdvertPayload signs an ADVERT payload and returns a new payload with the
// signature field (bytes 36–99) filled in.
//
// privKey must be the Ed25519 private key whose public key is embedded at
// bytes 0–31 of the payload. Accepts either a 32-byte seed or a 64-byte
// private key (seed ‖ public key). Returns an error if the key does not
// correspond to the public key in the payload.
func SignAdvertPayload(payload, privKey []byte) ([]byte, error) {
	if len(payload) < 100 {
		return nil, fmt.Errorf("meshpkt: ADVERT payload too short to sign (%d bytes)", len(payload))
	}

	var key ed25519.PrivateKey
	switch len(privKey) {
	case ed25519.SeedSize: // 32 bytes
		key = ed25519.NewKeyFromSeed(privKey)
	case ed25519.PrivateKeySize: // 64 bytes
		key = ed25519.PrivateKey(privKey)
	default:
		return nil, fmt.Errorf("meshpkt: Ed25519 private key must be 32 (seed) or 64 bytes, got %d", len(privKey))
	}

	pub := key.Public().(ed25519.PublicKey)
	if string(pub) != string(payload[0:32]) {
		return nil, fmt.Errorf("meshpkt: private key does not match the public key in ADVERT payload")
	}

	sig := ed25519.Sign(key, advertSignedMessage(payload))

	out := make([]byte, len(payload))
	copy(out, payload)
	copy(out[36:100], sig)
	return out, nil
}

// SignAdvert encodes adv, signs the payload with id, and returns a new Advert
// with the Signature field set. The adv.PublicKey must match id.PublicKey.
func SignAdvert(id Identity, adv Advert) (Advert, error) {
	if len(adv.PublicKey) != 32 {
		return Advert{}, fmt.Errorf("meshpkt: ADVERT public key must be 32 bytes")
	}
	for i := range 32 {
		if adv.PublicKey[i] != id.PublicKey[i] {
			return Advert{}, fmt.Errorf("meshpkt: ADVERT public key does not match identity")
		}
	}
	payload, err := EncodeAdvertPayload(adv)
	if err != nil {
		return Advert{}, err
	}
	signed, err := SignAdvertPayload(payload, id.Seed[:])
	if err != nil {
		return Advert{}, err
	}
	sig := signed[36:100]
	out := adv
	out.Signature = make([]byte, 64)
	copy(out.Signature, sig)
	return out, nil
}

// VerifyAdvert verifies the signature on adv.
// Returns nil if the signature is valid, or ErrAdvertBadSignature if not.
// All-zero signatures are treated as unsigned and return nil.
func VerifyAdvert(adv Advert) error {
	if len(adv.PublicKey) != 32 {
		return fmt.Errorf("meshpkt: ADVERT public key must be 32 bytes")
	}
	if len(adv.Signature) == 0 || allZero(adv.Signature) {
		return nil // unsigned
	}
	if len(adv.Signature) != 64 {
		return ErrAdvertBadSignature
	}
	payload, err := EncodeAdvertPayload(adv)
	if err != nil {
		return err
	}
	if !VerifyAdvertSignature(payload) {
		return ErrAdvertBadSignature
	}
	return nil
}

// DecodeAdvertPayload decodes an ADVERT payload applying all firmware
// validation rules. Returns an error if:
//   - payload < 100 bytes
//   - a non-zero signature fails verification
//   - flags declare GPS/feat1/feat2 but the bytes are missing
//   - GPS coordinates are outside valid ranges
func DecodeAdvertPayload(payload []byte) (Advert, error) {
	if len(payload) < 100 {
		return Advert{}, ErrAdvertTooShort
	}

	a := Advert{
		PublicKey: make([]byte, 32),
		Signature: make([]byte, 64),
	}
	copy(a.PublicKey, payload[0:32])
	a.Timestamp = time.Unix(int64(binary.LittleEndian.Uint32(payload[32:36])), 0)
	copy(a.Signature, payload[36:100])

	if !allZero(a.Signature) {
		if !ed25519.Verify(ed25519.PublicKey(a.PublicKey), advertSignedMessage(payload), a.Signature) {
			return Advert{}, ErrAdvertBadSignature
		}
	}

	if len(payload) <= 100 {
		return a, nil
	}
	return parseAdvertAppdata(payload, &a)
}

// DecodeAdvertPayloadStrict is an alias for DecodeAdvertPayload.
func DecodeAdvertPayloadStrict(payload []byte) (Advert, error) {
	return DecodeAdvertPayload(payload)
}

// SignedAdvertPacket is a one-step convenience builder that:
//  1. sets adv.PublicKey from id.PublicKey;
//  2. encodes the ADVERT payload;
//  3. signs it with id.Sign (Ed25519, matching firmware);
//  4. inserts the signature;
//  5. wraps everything in a MeshCore ADVERT packet.
//
// Callers should not need to pass both a public key and signature manually.
func SignedAdvertPacket(id Identity, adv Advert, opts ...Option) ([]byte, error) {
	adv.PublicKey = id.PublicKey[:]

	signed, err := SignAdvert(id, adv)
	if err != nil {
		return nil, err
	}
	payload, err := EncodeAdvertPayload(signed)
	if err != nil {
		return nil, err
	}

	o := &packetOptions{pathHashSize: defaultPathHashSize}
	for _, opt := range opts {
		opt(o)
	}
	return EncodePacket(Packet{
		Route:        RouteFlood,
		Type:         PayloadAdvert,
		PathHashSize: o.pathHashSize,
		Payload:      payload,
	})
}

// parseAdvertAppdata fills in the optional appdata fields starting at offset 100.
func parseAdvertAppdata(payload []byte, a *Advert) (Advert, error) {
	off := 100
	flags := payload[off]
	off++
	a.NodeType = flags & 0x0F

	if flags&0x10 != 0 {
		if off+8 > len(payload) {
			return Advert{}, ErrAdvertMissingGPS
		}
		lat := int32(binary.LittleEndian.Uint32(payload[off:]))
		lon := int32(binary.LittleEndian.Uint32(payload[off+4:]))
		a.Lat = float64(lat) / 1e6
		a.Lon = float64(lon) / 1e6
		if a.Lat < -90 || a.Lat > 90 {
			return Advert{}, ErrAdvertLatOutOfRange
		}
		if a.Lon < -180 || a.Lon > 180 {
			return Advert{}, ErrAdvertLonOutOfRange
		}
		a.HasGPS = true
		off += 8
	}

	if flags&0x20 != 0 {
		if off+2 > len(payload) {
			return Advert{}, ErrAdvertMissingFeat1
		}
		a.Feature1 = binary.LittleEndian.Uint16(payload[off:])
		a.HasFeat1 = true
		off += 2
	}

	if flags&0x40 != 0 {
		if off+2 > len(payload) {
			return Advert{}, ErrAdvertMissingFeat2
		}
		a.Feature2 = binary.LittleEndian.Uint16(payload[off:])
		a.HasFeat2 = true
		off += 2
	}

	if flags&0x80 != 0 && off < len(payload) {
		name := string(payload[off:])
		if idx := strings.IndexByte(name, 0); idx >= 0 {
			name = name[:idx]
		}
		a.Name = strings.TrimSpace(name)
	}

	return *a, nil
}
