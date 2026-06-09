package meshpkt

import (
	"encoding/binary"
	"fmt"
)

// GrpData holds the decoded content of a GRP_DATA (group datagram) payload.
// GRP_DATA uses the same crypto as GRP_TXT but carries binary data instead of text.
//
// Wire layout: [channel_hash:1][mac:2][ciphertext]
// Plaintext:   [data_type:2 LE][data_len:1][data...]
type GrpData struct {
	ChannelHash byte
	DataType    uint16
	Data        []byte
}

// DecodeGrpDataPayload decodes a GRP_DATA payload using the channel secret.
func DecodeGrpDataPayload(secret, payload []byte) (GrpData, error) {
	if len(secret) < cipherKeySize {
		return GrpData{}, fmt.Errorf("meshpkt: channel secret too short")
	}
	if len(payload) < 1+cipherMACSize {
		return GrpData{}, fmt.Errorf("meshpkt: GRP_DATA payload too short (%d bytes)", len(payload))
	}
	channelHash := payload[0]
	expected := ChannelHash(secret)
	if channelHash != expected {
		return GrpData{}, fmt.Errorf("meshpkt: GRP_DATA channel hash mismatch (got %02x, want %02x) — wrong channel secret?", channelHash, expected)
	}
	mac := payload[1:3]
	ciphertext := payload[3:]
	plaintext, ok, err := openMAC(secret[:cipherKeySize], mac, ciphertext)
	if err != nil {
		return GrpData{}, fmt.Errorf("meshpkt: GRP_DATA decrypt: %w", err)
	}
	if !ok {
		return GrpData{}, fmt.Errorf("meshpkt: GRP_DATA MAC verification failed — wrong channel secret?")
	}
	// Plaintext: [data_type:2 LE][data_len:1][data...]
	if len(plaintext) < 3 {
		return GrpData{}, fmt.Errorf("meshpkt: GRP_DATA plaintext too short (%d bytes)", len(plaintext))
	}
	dataType := binary.LittleEndian.Uint16(plaintext[0:2])
	dataLen := int(plaintext[2])
	data := plaintext[3:]
	if dataLen > len(data) {
		dataLen = len(data) // tolerate truncation
	}
	return GrpData{
		ChannelHash: channelHash,
		DataType:    dataType,
		Data:        data[:dataLen],
	}, nil
}

// DecodeGrpDataPayloadByName derives the channel secret from name and decodes a GRP_DATA payload.
func DecodeGrpDataPayloadByName(channelName string, payload []byte) (GrpData, error) {
	return DecodeGrpDataPayload(DeriveChannelSecret(channelName), payload)
}

// GrpDataPacket builds a complete GRP_DATA packet encrypted with the channel secret.
// dataType is an application-defined 16-bit type code; data carries the payload body.
func GrpDataPacket(secret []byte, dataType uint16, data []byte, opts ...Option) ([]byte, error) {
	if len(secret) < cipherKeySize {
		return nil, fmt.Errorf("meshpkt: channel secret too short")
	}
	if len(data) > 255 {
		return nil, fmt.Errorf("meshpkt: GRP_DATA data too long (%d bytes, max 255)", len(data))
	}
	o := &packetOptions{pathHashSize: defaultPathHashSize}
	for _, opt := range opts {
		opt(o)
	}
	// Plaintext: [data_type:2 LE][data_len:1][data...]
	plaintext := make([]byte, 3+len(data))
	binary.LittleEndian.PutUint16(plaintext[0:2], dataType)
	plaintext[2] = byte(len(data))
	copy(plaintext[3:], data)

	mac, ciphertext, err := sealMAC(secret[:cipherKeySize], plaintext)
	if err != nil {
		return nil, fmt.Errorf("meshpkt: GRP_DATA encrypt: %w", err)
	}
	payload := make([]byte, 0, 1+cipherMACSize+len(ciphertext))
	payload = append(payload, ChannelHash(secret))
	payload = append(payload, mac...)
	payload = append(payload, ciphertext...)

	return EncodePacket(Packet{
		Route:        RouteFlood,
		Type:         PayloadGrpData,
		PathHashSize: o.pathHashSize,
		Payload:      payload,
	})
}

// GrpDataPacketFromName derives the channel secret and builds a GRP_DATA packet.
func GrpDataPacketFromName(channelName string, dataType uint16, data []byte, opts ...Option) ([]byte, error) {
	return GrpDataPacket(DeriveChannelSecret(channelName), dataType, data, opts...)
}
