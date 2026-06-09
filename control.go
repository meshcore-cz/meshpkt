package meshpkt

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// Control holds the decoded content of a CONTROL payload.
//
// Wire layout: [flags:1][data...]
// SubType = flags >> 4 (upper nibble).
//
// Known sub-types:
//   - 0x8: DISCOVER_REQ  — node discovery request
//   - 0x9: DISCOVER_RESP — node discovery response
type Control struct {
	SubType byte // upper nibble of flags byte
	Flags   byte // raw flags byte
	Data    []byte

	// Populated for DISCOVER_REQ (SubType == 0x8)
	DiscoverReq *DiscoverReq

	// Populated for DISCOVER_RESP (SubType == 0x9)
	DiscoverResp *DiscoverResp
}

// ControlSubType constants for Control.SubType.
const (
	ControlSubDiscoverReq  byte = 0x8
	ControlSubDiscoverResp byte = 0x9
)

// DiscoverReq is the payload of a DISCOVER_REQ CONTROL sub-type.
//
// Wire layout (after flags byte):
//
//	[type_filter:1][tag:4 LE][since:4 LE (optional)]
type DiscoverReq struct {
	PrefixOnly bool   // lowest bit of flags
	TypeFilter byte   // bit per ADV_TYPE_* (1=chat, 2=repeater, 4=room, 8=sensor)
	Tag        uint32 // random tag echoed in response
	Since      uint32 // epoch timestamp filter (0 = no filter)
}

// DiscoverResp is the payload of a DISCOVER_RESP CONTROL sub-type.
//
// Wire layout (after flags byte):
//
//	[snr:1 int8 ×0.25][tag:4 LE][pubkey:8 or 32]
type DiscoverResp struct {
	NodeType byte    // lower nibble of flags (1=chat, 2=repeater, 3=room, 4=sensor)
	SNR      float64 // dB (int8 × 0.25)
	Tag      uint32  // reflected from DISCOVER_REQ
	PubKey   string  // hex-encoded 8-byte prefix or 32-byte full key
}

// DecodeControlPayload decodes a CONTROL payload.
func DecodeControlPayload(payload []byte) (Control, error) {
	if len(payload) < 1 {
		return Control{}, fmt.Errorf("meshpkt: CONTROL payload too short")
	}
	flags := payload[0]
	data := payload[1:]
	c := Control{
		SubType: flags >> 4,
		Flags:   flags,
		Data:    data,
	}

	switch c.SubType {
	case ControlSubDiscoverReq:
		req, err := decodeDiscoverReq(flags, data)
		if err == nil {
			c.DiscoverReq = &req
		}
	case ControlSubDiscoverResp:
		resp, err := decodeDiscoverResp(flags, data)
		if err == nil {
			c.DiscoverResp = &resp
		}
	}
	return c, nil
}

func decodeDiscoverReq(flags byte, data []byte) (DiscoverReq, error) {
	if len(data) < 5 {
		return DiscoverReq{}, fmt.Errorf("meshpkt: DISCOVER_REQ too short (%d bytes)", len(data))
	}
	d := DiscoverReq{
		PrefixOnly: flags&0x01 != 0,
		TypeFilter: data[0],
		Tag:        binary.LittleEndian.Uint32(data[1:5]),
	}
	if len(data) >= 9 {
		d.Since = binary.LittleEndian.Uint32(data[5:9])
	}
	return d, nil
}

func decodeDiscoverResp(flags byte, data []byte) (DiscoverResp, error) {
	if len(data) < 5 {
		return DiscoverResp{}, fmt.Errorf("meshpkt: DISCOVER_RESP too short (%d bytes)", len(data))
	}
	d := DiscoverResp{
		NodeType: flags & 0x0F,
		SNR:      float64(int8(data[0])) / 4,
		Tag:      binary.LittleEndian.Uint32(data[1:5]),
	}
	key := data[5:]
	if len(key) >= 32 {
		d.PubKey = hex.EncodeToString(key[:32])
	} else if len(key) >= 8 {
		d.PubKey = hex.EncodeToString(key[:8])
	} else if len(key) > 0 {
		d.PubKey = hex.EncodeToString(key)
	}
	return d, nil
}

// DiscoverReqPacket builds a CONTROL/DISCOVER_REQ packet.
// tag should be a random 32-bit value; since is an epoch timestamp (0 = all nodes).
func DiscoverReqPacket(typeFilter byte, tag, since uint32, prefixOnly bool, opts ...Option) ([]byte, error) {
	o := &packetOptions{pathHashSize: defaultPathHashSize}
	for _, opt := range opts {
		opt(o)
	}
	flags := byte(ControlSubDiscoverReq<<4) // 0x80
	if prefixOnly {
		flags |= 0x01
	}
	data := make([]byte, 9)
	data[0] = typeFilter
	binary.LittleEndian.PutUint32(data[1:5], tag)
	binary.LittleEndian.PutUint32(data[5:9], since)

	payload := append([]byte{flags}, data...)
	return EncodePacket(Packet{
		Route:        RouteFlood,
		Type:         PayloadControl,
		PathHashSize: o.pathHashSize,
		Payload:      payload,
	})
}
