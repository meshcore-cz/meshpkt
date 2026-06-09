package meshpkt

import (
	"encoding/binary"
	"fmt"
)

// DecodeAckPayload decodes an ACK payload.
//
// Wire layout: [crc32:4 LE]
// The CRC is computed over the original message's timestamp, text, and sender pubkey.
func DecodeAckPayload(payload []byte) (uint32, error) {
	if len(payload) < 4 {
		return 0, fmt.Errorf("meshpkt: ACK payload too short (%d bytes, need 4)", len(payload))
	}
	return binary.LittleEndian.Uint32(payload[:4]), nil
}

// AckPacket builds a complete ACK packet (FLOOD route) containing the given CRC32.
func AckPacket(crc uint32, opts ...Option) ([]byte, error) {
	o := &packetOptions{pathHashSize: defaultPathHashSize}
	for _, opt := range opts {
		opt(o)
	}
	payload := make([]byte, 4)
	binary.LittleEndian.PutUint32(payload, crc)
	return EncodePacket(Packet{
		Route:        RouteFlood,
		Type:         PayloadAck,
		PathHashSize: o.pathHashSize,
		Payload:      payload,
	})
}
