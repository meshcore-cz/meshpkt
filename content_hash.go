package meshpkt

import "crypto/sha256"

// Content hashing produces a route-independent logical identifier for a MeshCore
// packet, compatible with CoreScope. Two on-air representations of the same
// logical packet — differing only in route type, packet version, transport
// codes, or accumulated path hops — yield the same content hash. This makes it
// suitable for cross-route deduplication and ACK correlation.
//
// The digest is computed over a canonical input:
//
//	normal packets: SHA256( payload_type_byte || payload )
//	PayloadTrace:   SHA256( payload_type_byte || path_descriptor_uint16_le || payload )
//
// For PayloadTrace the one-byte path descriptor (high two bits = PathHashSize-1,
// low six bits = hop count) is reconstructed from the decoded packet and appended
// as a little-endian uint16, because a trace's hop count is part of its logical
// content. PathHashSize == 0 is treated as the EncodePacket default (2).

// ContentDigest returns the full SHA-256 content digest of an already-decoded,
// valid packet.
func ContentDigest(pkt Packet) [32]byte {
	input := []byte{byte(pkt.Type)}

	if pkt.Type == PayloadTrace {
		hashSize := pkt.PathHashSize
		if hashSize == 0 {
			hashSize = defaultPathHashSize
		}

		pathByte := byte((hashSize - 1) << 6)
		pathByte |= byte(pkt.HopCount())

		input = append(input, pathByte, 0x00)
	}

	input = append(input, pkt.Payload...)
	return sha256.Sum256(input)
}

// ContentHash returns the first 8 bytes of ContentDigest — a short
// CoreScope-compatible logical packet identifier.
func ContentHash(pkt Packet) [8]byte {
	digest := ContentDigest(pkt)
	var short [8]byte
	copy(short[:], digest[:8])
	return short
}

// DecodeContentDigest parses and validates raw OTA bytes with DecodePacket, then
// returns the full content digest. It does not introduce a second parser.
func DecodeContentDigest(raw []byte) ([32]byte, error) {
	pkt, err := DecodePacket(raw)
	if err != nil {
		return [32]byte{}, err
	}
	return ContentDigest(pkt), nil
}

// DecodeContentHash returns the first 8 bytes of DecodeContentDigest.
func DecodeContentHash(raw []byte) ([8]byte, error) {
	digest, err := DecodeContentDigest(raw)
	if err != nil {
		return [8]byte{}, err
	}
	var short [8]byte
	copy(short[:], digest[:8])
	return short, nil
}
