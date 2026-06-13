package meshpkt

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// PubKeyHashSize is the number of public-key bytes used as a node's MeshCore
// routing hash / dest_hash / src_hash.
const pubKeySize = 32

// TextAckCRC computes the ACK CRC a recipient must return for a received TXT_MSG,
// matching MeshCore firmware BaseChatMesh::composeMsgPacket:
//
//	crc = SHA256( timestamp[4 LE] | (attempt & 3)[1] | text | senderPubKey[32] )[0:4]
//
// interpreted as a little-endian uint32. senderPubKey is the 32-byte Ed25519
// public key of the TXT_MSG's sender (its full identity key, not the 1-byte hash).
// text is the message text without any trailing NUL or zero padding.
func TextAckCRC(timestamp uint32, attempt byte, text string, senderPubKey []byte) uint32 {
	temp := make([]byte, 0, 5+len(text))
	var ts [4]byte
	binary.LittleEndian.PutUint32(ts[:], timestamp)
	temp = append(temp, ts[:]...)
	temp = append(temp, attempt&0x03)
	temp = append(temp, text...)

	h := sha256.New()
	h.Write(temp)
	h.Write(senderPubKey)
	sum := h.Sum(nil)
	return binary.LittleEndian.Uint32(sum[:4])
}

// TextAckPacket builds the complete flood-routed ACK packet a recipient returns
// for a received TXT_MSG, computing the CRC via TextAckCRC.
func TextAckPacket(timestamp uint32, attempt byte, text string, senderPubKey []byte, opts ...Option) ([]byte, error) {
	if len(senderPubKey) != pubKeySize {
		return nil, fmt.Errorf("meshpkt: sender public key must be %d bytes, got %d", pubKeySize, len(senderPubKey))
	}
	return AckPacket(TextAckCRC(timestamp, attempt, text, senderPubKey), opts...)
}

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
