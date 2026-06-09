package meshpkt

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// TracePayload holds the decoded content of a TRACE (0x09) packet.
//
// TRACE is a plaintext diagnostic packet — no dest/src hash, no MAC, no
// signature. It is always sent ROUTE_TYPE_DIRECT (the firmware rejects flood
// routing for traces).
//
// The outer Packet.Path field is repurposed as an SNR accumulator: each byte
// is a received SNR encoded as int8 × 4. Use TraceSNRs(pkt.Path) to convert.
// The payload proper begins after those path bytes.
//
// Payload wire layout: [tag:4 LE][auth_code:4 LE][flags:1][route_hashes...]
//
// flags & 0x03 defines the width of each route hash:
//
//	0 → 1 byte  (common)
//	1 → 2 bytes
//	2 → 4 bytes
//	3 → 8 bytes
//
// auth_code is an opaque value forwarded verbatim — the firmware core does
// not validate it cryptographically.
type TracePayload struct {
	Tag       uint32 // random tag, echoed in companion push notification
	AuthCode  uint32 // opaque auth value (not cryptographically verified)
	Flags     byte   // low 2 bits = route-hash width exponent
	RouteData []byte // raw concatenated route hash bytes
}

// HashWidth returns the width in bytes of each route hash (1, 2, 4, or 8).
func (p TracePayload) HashWidth() int {
	return 1 << (p.Flags & 0x03)
}

// RouteHashes splits RouteData into individual per-hop hash byte slices.
func (p TracePayload) RouteHashes() [][]byte {
	width := p.HashWidth()
	if len(p.RouteData) == 0 {
		return nil
	}
	n := len(p.RouteData) / width
	hashes := make([][]byte, n)
	for i := range hashes {
		h := make([]byte, width)
		copy(h, p.RouteData[i*width:(i+1)*width])
		hashes[i] = h
	}
	return hashes
}

// TraceSNRs converts the SNR accumulator bytes from a TRACE packet's Path
// field into dB values. Each path byte is an int8 equal to SNR × 4
// (e.g. 0x1D = 29 → +7.25 dB, 0xF4 = -12 → -3.00 dB).
//
// Pass Packet.Path from a decoded TRACE packet.
func TraceSNRs(path []byte) []float64 {
	snrs := make([]float64, len(path))
	for i, b := range path {
		snrs[i] = float64(int8(b)) / 4.0
	}
	return snrs
}

// DecodeTracePayload decodes the Packet.Payload bytes of a TRACE packet.
// SNR values accumulated during forwarding live in Packet.Path — call
// TraceSNRs(pkt.Path) to decode them.
func DecodeTracePayload(payload []byte) (TracePayload, error) {
	// Minimum: tag(4) + auth_code(4) + flags(1) = 9 bytes.
	if len(payload) < 9 {
		return TracePayload{}, fmt.Errorf("meshpkt: TRACE payload too short (%d bytes, need at least 9)", len(payload))
	}
	t := TracePayload{
		Tag:       binary.LittleEndian.Uint32(payload[0:4]),
		AuthCode:  binary.LittleEndian.Uint32(payload[4:8]),
		Flags:     payload[8],
		RouteData: make([]byte, len(payload)-9),
	}
	copy(t.RouteData, payload[9:])
	return t, nil
}

// TracePacket builds a new TRACE packet with an empty SNR accumulator
// (path_length = 0). Each repeater that forwards the packet appends its
// received SNR × 4 to the outer path field.
//
// routeHashes is the concatenated route hash bytes. The hash width is
// determined by flags & 0x03 (0→1B, 1→2B, 2→4B, 3→8B).
//
// TRACE always uses ROUTE_TYPE_DIRECT (0x02).
func TracePacket(tag, authCode uint32, flags byte, routeHashes []byte) ([]byte, error) {
	payload := make([]byte, 9+len(routeHashes))
	binary.LittleEndian.PutUint32(payload[0:4], tag)
	binary.LittleEndian.PutUint32(payload[4:8], authCode)
	payload[8] = flags
	copy(payload[9:], routeHashes)
	return EncodePacket(Packet{
		Route:        RouteDirect,
		Type:         PayloadTrace,
		PathHashSize: 1, // SNR accumulator uses 1 byte per entry
		Payload:      payload,
	})
}

// traceRouteHashHex returns route hashes as hex strings, for the ops/CLI layer.
func traceRouteHashHex(t TracePayload) []any {
	hashes := t.RouteHashes()
	out := make([]any, len(hashes))
	for i, h := range hashes {
		out[i] = hex.EncodeToString(h)
	}
	return out
}

// traceSNRStrings formats SNR float values as "%.2f" strings, for the ops/CLI layer.
func traceSNRStrings(snrs []float64) []any {
	out := make([]any, len(snrs))
	for i, s := range snrs {
		out[i] = fmt.Sprintf("%.2f", s)
	}
	return out
}
