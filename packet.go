package meshpkt

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Wire-format limits and version constants.
const (
	MaxPathBytes      = 64  // MAX_PATH_SIZE in firmware
	MaxPayloadBytes   = 184 // MAX_PACKET_PAYLOAD in firmware
	MaxHopCount       = 63  // hop count field is 6 bits
	CurrentPayloadVer = 0   // only version v0 is defined and sent by firmware
)

const defaultPathHashSize = 2 // default path hash size for new packets

// Sentinel errors returned by the encoder and decoder. All are exported so
// callers can use errors.Is for precise error handling.
var (
	ErrUnsupportedVersion  = errors.New("meshpkt: unsupported payload version (must be 0)")
	ErrInvalidRoute        = errors.New("meshpkt: invalid route type")
	ErrInvalidPayloadType  = errors.New("meshpkt: invalid payload type (must be 0x00–0x0F)")
	ErrInvalidPathHashSize = errors.New("meshpkt: invalid path hash size (must be 1, 2, or 3; mode 0b11 is reserved)")
	ErrUnalignedPath       = errors.New("meshpkt: path length is not aligned to PathHashSize")
	ErrPathTooLong         = errors.New("meshpkt: path exceeds 64-byte limit")
	ErrPayloadTooLong      = errors.New("meshpkt: payload exceeds 184-byte limit")
	ErrTooManyHops         = errors.New("meshpkt: hop count exceeds maximum 63")
)

// Option configures packet-building behaviour. It is accepted by every packet
// encoder (GroupTextPacket, DirectTextPacket, AckPacket, …).
type Option func(*packetOptions)

type packetOptions struct {
	pathHashSize int
}

// WithPathHashSize sets the path hash size in bytes (1–3; default 2).
// This controls the path_len encoding (bits 7-6). For a fresh flood packet
// with 0 hops there are no path bytes, so this only affects the path_len byte.
func WithPathHashSize(n int) Option {
	return func(o *packetOptions) {
		o.pathHashSize = n
	}
}

// RouteType is the 2-bit routing mode encoded in header bits 1-0.
type RouteType byte

const (
	RouteTransportFlood  RouteType = 0x00 // flood via transport relay
	RouteFlood           RouteType = 0x01 // direct flood
	RouteDirect          RouteType = 0x02 // direct (unicast)
	RouteTransportDirect RouteType = 0x03 // unicast via transport relay
)

// IsTransport reports whether transport codes are present in the wire packet.
func (r RouteType) IsTransport() bool {
	return r == RouteTransportFlood || r == RouteTransportDirect
}

// String returns a human-readable name for the route type.
func (r RouteType) String() string {
	switch r {
	case RouteTransportFlood:
		return "TRANSPORT_FLOOD"
	case RouteFlood:
		return "FLOOD"
	case RouteDirect:
		return "DIRECT"
	case RouteTransportDirect:
		return "TRANSPORT_DIRECT"
	default:
		return fmt.Sprintf("route(0x%02x)", byte(r))
	}
}

// PayloadType is the 4-bit payload type encoded in header bits 5-2.
type PayloadType byte

const (
	PayloadReq       PayloadType = 0x00 // request with dest/src hashes + MAC
	PayloadResponse  PayloadType = 0x01 // response to REQ or ANON_REQ
	PayloadTxtMsg    PayloadType = 0x02 // direct text message (encrypted)
	PayloadAck       PayloadType = 0x03 // acknowledgement (CRC only)
	PayloadAdvert    PayloadType = 0x04 // node advertisement (unencrypted)
	PayloadGrpTxt    PayloadType = 0x05 // group/channel text message (encrypted)
	PayloadGrpData   PayloadType = 0x06 // group datagram (unencrypted)
	PayloadAnonReq   PayloadType = 0x07 // anonymous request
	PayloadPath      PayloadType = 0x08 // returned path
	PayloadTrace     PayloadType = 0x09 // path trace (collects SNR per hop)
	PayloadMultipart PayloadType = 0x0A // packet in a sequence
	PayloadControl   PayloadType = 0x0B // unencrypted control data
	// 0x0C–0x0E are reserved; rejected on encode and decode.
	PayloadRawCustom PayloadType = 0x0F // custom/raw packet
)

// AllRouteTypes lists every defined RouteType in wire-format order.
// Useful for code generators and UI dropdowns.
var AllRouteTypes = []RouteType{
	RouteTransportFlood,
	RouteFlood,
	RouteDirect,
	RouteTransportDirect,
}

// AllPayloadTypes lists every defined PayloadType in wire-format order.
// Useful for code generators and UI dropdowns.
var AllPayloadTypes = []PayloadType{
	PayloadReq, PayloadResponse, PayloadTxtMsg, PayloadAck,
	PayloadAdvert, PayloadGrpTxt, PayloadGrpData, PayloadAnonReq,
	PayloadPath, PayloadTrace, PayloadMultipart, PayloadControl,
	PayloadRawCustom,
}

// String returns the payload type name (e.g. "GRP_TXT").
func (t PayloadType) String() string {
	switch t {
	case PayloadReq:
		return "REQ"
	case PayloadResponse:
		return "RESPONSE"
	case PayloadTxtMsg:
		return "TXT_MSG"
	case PayloadAck:
		return "ACK"
	case PayloadAdvert:
		return "ADVERT"
	case PayloadGrpTxt:
		return "GRP_TXT"
	case PayloadGrpData:
		return "GRP_DATA"
	case PayloadAnonReq:
		return "ANON_REQ"
	case PayloadPath:
		return "PATH"
	case PayloadTrace:
		return "TRACE"
	case PayloadMultipart:
		return "MULTIPART"
	case PayloadControl:
		return "CONTROL"
	case PayloadRawCustom:
		return "RAW_CUSTOM"
	default:
		return fmt.Sprintf("unknown(0x%02x)", byte(t))
	}
}

// Packet represents a decoded MeshCore radio packet.
type Packet struct {
	Route          RouteType
	Type           PayloadType
	Version        byte      // payload version, currently always 0
	TransportCodes [2]uint16 // only meaningful when Route.IsTransport()
	PathHashSize   int       // bytes per hop hash: 1, 2, or 3
	Path           []byte    // raw hop bytes; length = HopCount() × PathHashSize
	Payload        []byte    // raw payload bytes
}

// HopCount returns the number of hops encoded in the path.
func (p Packet) HopCount() int {
	if p.PathHashSize <= 0 {
		return 0
	}
	return len(p.Path) / p.PathHashSize
}

// Hops returns the path as a slice of per-hop hash bytes.
func (p Packet) Hops() [][]byte {
	size := p.PathHashSize
	if size <= 0 || len(p.Path) == 0 {
		return nil
	}
	if len(p.Path)%size != 0 {
		return nil
	}
	hops := make([][]byte, 0, len(p.Path)/size)
	for i := 0; i < len(p.Path); i += size {
		hop := make([]byte, size)
		copy(hop, p.Path[i:i+size])
		hops = append(hops, hop)
	}
	return hops
}

// EncodePacket serialises a Packet to its wire representation, applying all
// MeshCore firmware validation rules. Returns a sentinel error for any field
// that firmware would reject.
//
// PathHashSize defaults to 2 when zero.
func EncodePacket(p Packet) ([]byte, error) {
	if p.PathHashSize == 0 {
		p.PathHashSize = defaultPathHashSize
	}
	if p.Version != CurrentPayloadVer {
		return nil, ErrUnsupportedVersion
	}
	if p.Route > RouteTransportDirect {
		return nil, ErrInvalidRoute
	}
	if p.Type > 0x0f {
		return nil, ErrInvalidPayloadType
	}
	if p.PathHashSize < 1 || p.PathHashSize > 3 {
		return nil, ErrInvalidPathHashSize
	}
	if len(p.Path)%p.PathHashSize != 0 {
		return nil, ErrUnalignedPath
	}
	if len(p.Path) > MaxPathBytes {
		return nil, ErrPathTooLong
	}
	if len(p.Payload) > MaxPayloadBytes {
		return nil, ErrPayloadTooLong
	}
	if p.HopCount() > MaxHopCount {
		return nil, ErrTooManyHops
	}

	header := (p.Version << 6) | (byte(p.Type) << 2) | byte(p.Route)
	pathLen := byte((p.PathHashSize-1)<<6) | byte(p.HopCount())

	size := 2 + len(p.Path) + len(p.Payload)
	if p.Route.IsTransport() {
		size += 4
	}
	buf := make([]byte, 0, size)
	buf = append(buf, header)
	if p.Route.IsTransport() {
		buf = binary.LittleEndian.AppendUint16(buf, p.TransportCodes[0])
		buf = binary.LittleEndian.AppendUint16(buf, p.TransportCodes[1])
	}
	buf = append(buf, pathLen)
	buf = append(buf, p.Path...)
	buf = append(buf, p.Payload...)
	return buf, nil
}

// DecodePacket parses a wire-format MeshCore packet, applying all firmware
// validation rules. Returns ErrInvalidPathHashSize for reserved path mode
// 0b11 and ErrUnsupportedVersion for version > 0.
func DecodePacket(raw []byte) (Packet, error) {
	if len(raw) < 2 {
		return Packet{}, fmt.Errorf("meshpkt: packet too short (%d bytes, need at least 2)", len(raw))
	}

	var p Packet
	i := 0

	header := raw[i]
	i++
	p.Route = RouteType(header & 0x03)
	p.Type = PayloadType((header >> 2) & 0x0f)
	p.Version = header >> 6

	if p.Version != CurrentPayloadVer {
		return Packet{}, ErrUnsupportedVersion
	}

	if p.Route.IsTransport() {
		if i+4 > len(raw) {
			return Packet{}, fmt.Errorf("meshpkt: truncated: transport_codes need 4 bytes at offset %d, have %d", i, len(raw)-i)
		}
		p.TransportCodes[0] = binary.LittleEndian.Uint16(raw[i:])
		p.TransportCodes[1] = binary.LittleEndian.Uint16(raw[i+2:])
		i += 4
	}

	if i >= len(raw) {
		return Packet{}, fmt.Errorf("meshpkt: missing path_len byte")
	}
	pathLen := raw[i]
	i++

	// Top 2 bits are (hashSize-1); value 0b11 is reserved by firmware.
	if pathLen>>6 == 0x03 {
		return Packet{}, ErrInvalidPathHashSize
	}
	p.PathHashSize = int(pathLen>>6) + 1
	hopCount := int(pathLen & 0x3f)
	pathBytes := hopCount * p.PathHashSize

	if pathBytes > MaxPathBytes {
		return Packet{}, ErrPathTooLong
	}
	if i+pathBytes > len(raw) {
		return Packet{}, fmt.Errorf("meshpkt: truncated: path needs %d bytes at offset %d, have %d", pathBytes, i, len(raw)-i)
	}
	p.Path = make([]byte, pathBytes)
	copy(p.Path, raw[i:i+pathBytes])
	i += pathBytes

	p.Payload = make([]byte, len(raw)-i)
	copy(p.Payload, raw[i:])

	if len(p.Payload) > MaxPayloadBytes {
		return Packet{}, ErrPayloadTooLong
	}
	return p, nil
}
