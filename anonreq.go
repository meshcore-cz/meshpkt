package meshpkt

import (
	"encoding/binary"
	"fmt"
	"time"
)

// AnonReq holds the decoded content of an ANON_REQ payload.
//
// ANON_REQ differs from REQ by embedding the sender's full 32-byte Ed25519
// public key in the payload (instead of just the 1-byte hash), allowing the
// recipient to derive the shared secret without prior key exchange.
//
// Wire layout: [dest_hash:1][sender_ed25519_pubkey:32][mac:2][ciphertext]
// ECDH key:    recipient.SharedSecret(senderPublicKey)[:16]
// Plaintext:   [timestamp:4 LE][data...]
type AnonReq struct {
	DestHash     byte
	SenderPubKey []byte // 32-byte sender Ed25519 public key
	Timestamp    time.Time
	Data         []byte // decrypted request body after timestamp
}

// AnonReqPacket builds a complete ANON_REQ packet.
//
// destPublicKey is the recipient's 32-byte Ed25519 public key.
// sender is the sender's Ed25519 Identity; the public key is embedded in the
// payload so the recipient can derive the shared secret without prior exchange.
//
// The shared secret is derived via sender.SharedSecret(destPublicKey).
func AnonReqPacket(destPublicKey [32]byte, sender Identity, data []byte, opts ...Option) ([]byte, error) {
	o := &packetOptions{pathHashSize: defaultPathHashSize}
	for _, opt := range opts {
		opt(o)
	}

	shared, err := sender.SharedSecret(destPublicKey)
	if err != nil {
		return nil, fmt.Errorf("meshpkt: ANON_REQ ECDH: %w", err)
	}

	// Plaintext: [timestamp:4 LE][data...]
	ts := time.Now()
	plain := make([]byte, 4+len(data))
	binary.LittleEndian.PutUint32(plain[0:4], uint32(ts.Unix()))
	copy(plain[4:], data)

	mac, ciphertext, err := sealMAC(shared[:cipherKeySize], plain)
	if err != nil {
		return nil, fmt.Errorf("meshpkt: ANON_REQ encrypt: %w", err)
	}

	// payload = [dest_hash:1][sender_ed25519_pubkey:32][mac:2][ciphertext]
	payload := make([]byte, 0, 1+32+cipherMACSize+len(ciphertext))
	payload = append(payload, destPublicKey[0])       // dest_hash
	payload = append(payload, sender.PublicKey[:]...) // Ed25519 sender public key
	payload = append(payload, mac...)
	payload = append(payload, ciphertext...)

	return EncodePacket(Packet{
		Route:        RouteFlood,
		Type:         PayloadAnonReq,
		PathHashSize: o.pathHashSize,
		Payload:      payload,
	})
}

// DecodeAnonReqPayload decodes an ANON_REQ payload using the recipient's
// Ed25519 Identity. The sender's Ed25519 public key is extracted from the
// payload and used to derive the shared secret via
// recipient.SharedSecret(senderPublicKey).
//
// AnonReq.SenderPubKey in the result is the sender's Ed25519 public key.
func DecodeAnonReqPayload(payload []byte, recipient Identity) (AnonReq, error) {
	// payload = [dest_hash:1][sender_ed25519_pubkey:32][mac:2][ciphertext]
	if len(payload) < 1+32+cipherMACSize {
		return AnonReq{}, fmt.Errorf("meshpkt: ANON_REQ payload too short (%d bytes)", len(payload))
	}
	destHash := payload[0]
	senderPub := make([]byte, 32)
	copy(senderPub, payload[1:33])
	mac := payload[33:35]
	ciphertext := payload[35:]

	// Derive shared secret from recipient's identity + embedded sender Ed25519 public key.
	var senderPubKey [32]byte
	copy(senderPubKey[:], senderPub)
	shared, err := recipient.SharedSecret(senderPubKey)
	if err != nil {
		return AnonReq{}, fmt.Errorf("meshpkt: ANON_REQ ECDH: %w", err)
	}

	plaintext, ok, err := openMAC(shared[:cipherKeySize], mac, ciphertext)
	if err != nil {
		return AnonReq{}, fmt.Errorf("meshpkt: ANON_REQ decrypt: %w", err)
	}
	if !ok {
		return AnonReq{}, fmt.Errorf("meshpkt: ANON_REQ MAC verification failed — wrong identity?")
	}

	if len(plaintext) < 4 {
		return AnonReq{}, fmt.Errorf("meshpkt: ANON_REQ plaintext too short (%d bytes)", len(plaintext))
	}
	ts := time.Unix(int64(binary.LittleEndian.Uint32(plaintext[0:4])), 0)

	return AnonReq{
		DestHash:     destHash,
		SenderPubKey: senderPub,
		Timestamp:    ts,
		Data:         plaintext[4:],
	}, nil
}

