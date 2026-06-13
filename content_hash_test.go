package meshpkt

import (
	"encoding/hex"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func TestContentDigestNormalGrpTxt(t *testing.T) {
	// 0x15 = FLOOD + GRP_TXT, 0x00 = empty path, payload = aa bb cc.
	// Canonical input = 05 aa bb cc.
	const wantDigest = "6826cc834e0067f2e52aa539a2437267c3b2ab61248dbec04c6d792789989575"
	const wantShort = "6826cc834e0067f2"

	digest, err := DecodeContentDigest(mustHex(t, "1500aabbcc"))
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(digest[:]); got != wantDigest {
		t.Fatalf("digest = %s, want %s", got, wantDigest)
	}

	short, err := DecodeContentHash(mustHex(t, "1500aabbcc"))
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(short[:]); got != wantShort {
		t.Fatalf("short = %s, want %s", got, wantShort)
	}

	// The in-memory API yields the same result for an already-decoded packet.
	pkt := Packet{Type: PayloadGrpTxt, Payload: mustHex(t, "aabbcc")}
	if d := ContentDigest(pkt); hex.EncodeToString(d[:]) != wantDigest {
		t.Fatalf("ContentDigest(pkt) = %x, want %s", d, wantDigest)
	}
	if h := ContentHash(pkt); hex.EncodeToString(h[:]) != wantShort {
		t.Fatalf("ContentHash(pkt) = %x, want %s", h, wantShort)
	}
}

func TestContentDigestRouteIndependence(t *testing.T) {
	// Same logical GRP_TXT payload (aabbcc) over three different routes/paths:
	//   FLOOD no hops; DIRECT with two 2-byte path entries; TRANSPORT_FLOOD with two transport codes.
	variants := []string{
		"1500aabbcc",
		"164211223344aabbcc",
		"140102030400aabbcc",
	}
	var first [32]byte
	for i, v := range variants {
		d, err := DecodeContentDigest(mustHex(t, v))
		if err != nil {
			t.Fatalf("variant %d (%s): %v", i, v, err)
		}
		if i == 0 {
			first = d
			continue
		}
		if d != first {
			t.Fatalf("variant %d (%s) digest = %x, want %x (route must not affect the hash)", i, v, d, first)
		}
	}
}

func TestContentDigestTrace(t *testing.T) {
	// Canonical TRACE input = 09 01 00 01 02 03 (type 0x09, path descriptor 0x0100, payload 010203).
	// Path descriptor 0x01 => PathHashSize 1, hop count 1.
	const wantDigest = "d11c2a0fede26dfd0dcf42a347f4a29e4371760bea60d37a04f19884ec1a1556"
	const wantShort = "d11c2a0fede26dfd"

	// In-memory packet with one 1-byte hop (the hop value itself must not affect the hash).
	pkt := Packet{Route: RouteFlood, Type: PayloadTrace, PathHashSize: 1, Path: []byte{0x99}, Payload: mustHex(t, "010203")}
	if d := ContentDigest(pkt); hex.EncodeToString(d[:]) != wantDigest {
		t.Fatalf("ContentDigest(trace) = %x, want %s", d, wantDigest)
	}
	if h := ContentHash(pkt); hex.EncodeToString(h[:]) != wantShort {
		t.Fatalf("ContentHash(trace) = %x, want %s", h, wantShort)
	}

	// Decoded from real OTA bytes yields the same digest.
	raw, err := EncodePacket(pkt)
	if err != nil {
		t.Fatal(err)
	}
	d, err := DecodeContentDigest(raw)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(d[:]) != wantDigest {
		t.Fatalf("DecodeContentDigest(trace OTA) = %x, want %s", d, wantDigest)
	}

	// A different hop value (same hop count) must hash identically.
	pkt2 := pkt
	pkt2.Path = []byte{0x42}
	if ContentDigest(pkt2) != ContentDigest(pkt) {
		t.Fatalf("trace hop value must not affect the content hash")
	}
}

func TestDecodeContentDigestRejectsMalformed(t *testing.T) {
	cases := map[string]string{
		"missing header":            "",
		"missing path descriptor":   "15",
		"truncated transport codes": "1401",
		"path bytes exceed length":  "1541",
		"reserved path-hash-size":   "15c0",
	}
	for name, h := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeContentDigest(mustHex(t, h)); err == nil {
				t.Fatalf("expected error for %s (%q)", name, h)
			}
		})
	}
}
