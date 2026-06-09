package meshpkt

import (
	"encoding/binary"
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
//	[flags:1][lat?:4 int32 LE, ×1e-6°][lon?:4 int32 LE, ×1e-6°][feat1?:2][feat2?:2][name?:string]
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
	Name      string    // node name (empty if not advertised)
}

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

	// Node name.
	if adv.Name != "" {
		buf = append(buf, []byte(adv.Name)...)
	}

	return buf, nil
}

// DecodeAdvertPayload decodes an ADVERT payload. Returns an error only if the
// payload is shorter than the required 100-byte fixed prefix; optional appdata
// fields are parsed on a best-effort basis.
func DecodeAdvertPayload(payload []byte) (Advert, error) {
	// Fixed prefix: pubkey(32) + ts(4) + sig(64) = 100 bytes minimum.
	if len(payload) < 100 {
		return Advert{}, fmt.Errorf("meshpkt: ADVERT payload too short (%d bytes, need at least 100)", len(payload))
	}

	a := Advert{
		PublicKey: make([]byte, 32),
		Signature: make([]byte, 64),
	}
	copy(a.PublicKey, payload[0:32])
	a.Timestamp = time.Unix(int64(binary.LittleEndian.Uint32(payload[32:36])), 0)
	copy(a.Signature, payload[36:100])

	if len(payload) <= 100 {
		return a, nil
	}

	// Appdata starts at offset 100.
	off := 100
	flags := payload[off]
	off++
	a.NodeType = flags & 0x0F

	// Bit 4 (0x10): has location — lat/lon as int32 LE, degrees × 1e6.
	if flags&0x10 != 0 {
		if off+8 <= len(payload) {
			lat := int32(binary.LittleEndian.Uint32(payload[off:]))
			lon := int32(binary.LittleEndian.Uint32(payload[off+4:]))
			a.Lat = float64(lat) / 1e6
			a.Lon = float64(lon) / 1e6
			a.HasGPS = true
		}
		off += 8
	}

	// Bit 5 (0x20): has feature 1 (2 bytes, reserved).
	if flags&0x20 != 0 {
		off += 2
	}

	// Bit 6 (0x40): has feature 2 (2 bytes, reserved).
	if flags&0x40 != 0 {
		off += 2
	}

	// Bit 7 (0x80): has name — remaining bytes.
	if flags&0x80 != 0 && off < len(payload) {
		name := string(payload[off:])
		if idx := strings.IndexByte(name, 0); idx >= 0 {
			name = name[:idx]
		}
		a.Name = strings.TrimSpace(name)
	}

	return a, nil
}
