package meshpkt

import (
	"encoding/binary"
	"fmt"
)

// MultipartPayload holds the decoded content of a MULTIPART (0x0A) packet.
//
// MULTIPART is currently used only to repeat ACK packets with delays to
// improve delivery reliability on lossy links. It is NOT a general-purpose
// fragmentation protocol — there is no sequence ID, fragment index, or
// reassembly buffer.
//
// Wire layout: [descriptor:1][inner_payload...]
//
//	descriptor = (remaining << 4) | inner_type
//	remaining  = number of MULTIPART packets still to be sent after this one
//	inner_type = PayloadType of the wrapped content (currently ACK only)
//
// Inner types other than ACK are currently ignored by the firmware (marked
// FUTURE in Mesh.cpp).
type MultipartPayload struct {
	Remaining    byte        // additional packets still to follow (0 = last)
	InnerType    PayloadType // payload type of the wrapped content
	InnerPayload []byte      // raw bytes of the inner payload
}

// DecodeMultipartPayload decodes a MULTIPART payload.
func DecodeMultipartPayload(payload []byte) (MultipartPayload, error) {
	if len(payload) < 1 {
		return MultipartPayload{}, fmt.Errorf("meshpkt: MULTIPART payload too short")
	}
	return MultipartPayload{
		Remaining:    payload[0] >> 4,
		InnerType:    PayloadType(payload[0] & 0x0F),
		InnerPayload: payload[1:],
	}, nil
}

// MultipartAckPacket builds a MULTIPART packet wrapping an ACK payload.
//
// remaining is the number of additional MULTIPART ACK packets the sender
// will still transmit after this one (0 means this is the last repetition).
// crc is the CRC32 of the original message being acknowledged.
//
// MULTIPART ACKs use ROUTE_TYPE_DIRECT (0x02) when a direct path is known.
func MultipartAckPacket(remaining byte, crc uint32, opts ...Option) ([]byte, error) {
	o := &packetOptions{pathHashSize: defaultPathHashSize}
	for _, opt := range opts {
		opt(o)
	}
	descriptor := (remaining << 4) | byte(PayloadAck)
	ackBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(ackBytes, crc)
	payload := append([]byte{descriptor}, ackBytes...)
	return EncodePacket(Packet{
		Route:        RouteDirect,
		Type:         PayloadMultipart,
		PathHashSize: o.pathHashSize,
		Payload:      payload,
	})
}
