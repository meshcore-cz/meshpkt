package meshpkt

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"time"
)

// AnonReq holds the decoded content of an ANON_REQ payload.
//
// ANON_REQ differs from REQ by embedding the sender's full 32-byte public key
// in the payload (instead of just the 1-byte hash), allowing the recipient to
// derive the shared secret without prior key exchange.
//
// Wire layout: [dest_hash:1][sender_pubkey:32][mac:2][ciphertext]
// ECDH key:    X25519(dest_priv, sender_pub)[:16]
// Plaintext:   [timestamp:4 LE][data...]
type AnonReq struct {
	DestHash     byte
	SenderPubKey []byte // 32-byte sender public key (Ed25519)
	Timestamp    time.Time
	Data         []byte // decrypted request body after timestamp
}

// DecodeAnonReqPayload decodes an ANON_REQ payload using the recipient's private key.
// The shared secret is derived on-the-fly from the sender public key embedded in the payload.
func DecodeAnonReqPayload(payload []byte, myPrivHex string) (AnonReq, error) {
	// payload = [dest_hash:1][sender_pubkey:32][mac:2][ciphertext]
	if len(payload) < 1+32+cipherMACSize {
		return AnonReq{}, fmt.Errorf("meshpkt: ANON_REQ payload too short (%d bytes)", len(payload))
	}
	destHash := payload[0]
	senderPub := make([]byte, 32)
	copy(senderPub, payload[1:33])
	mac := payload[33:35]
	ciphertext := payload[35:]

	// Derive shared secret from recipient's private key + embedded sender public key.
	senderPubHex := hex.EncodeToString(senderPub)
	shared, err := SharedSecret(myPrivHex, senderPubHex)
	if err != nil {
		return AnonReq{}, fmt.Errorf("meshpkt: ANON_REQ ECDH: %w", err)
	}

	plaintext, ok, err := openMAC(shared[:cipherKeySize], mac, ciphertext)
	if err != nil {
		return AnonReq{}, fmt.Errorf("meshpkt: ANON_REQ decrypt: %w", err)
	}
	if !ok {
		return AnonReq{}, fmt.Errorf("meshpkt: ANON_REQ MAC verification failed — wrong private key?")
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

// AnonReqPacket builds a complete ANON_REQ packet.
//
// destPubKey is the 32-byte destination public key (raw bytes).
// myPrivHex is the sender's private key in hex.
// data is the request body appended after the 4-byte timestamp.
//
// The sender's public key is embedded in the payload; the shared secret
// is X25519(myPriv, destPub)[:16].
func AnonReqPacket(destPubKey []byte, myPrivHex string, data []byte, opts ...Option) ([]byte, error) {
	if len(destPubKey) != 32 {
		return nil, fmt.Errorf("meshpkt: ANON_REQ dest public key must be 32 bytes, got %d", len(destPubKey))
	}
	o := &packetOptions{pathHashSize: defaultPathHashSize}
	for _, opt := range opts {
		opt(o)
	}

	destPubHex := hex.EncodeToString(destPubKey)
	myPubHex, err := PublicKeyFromPrivate(myPrivHex)
	if err != nil {
		return nil, fmt.Errorf("meshpkt: ANON_REQ derive public key: %w", err)
	}
	myPub, err := ParsePublicKey(myPubHex)
	if err != nil {
		return nil, err
	}
	shared, err := SharedSecret(myPrivHex, destPubHex)
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

	// payload = [dest_hash:1][my_pubkey:32][mac:2][ciphertext]
	payload := make([]byte, 0, 1+32+cipherMACSize+len(ciphertext))
	payload = append(payload, destPubKey[0]) // dest_hash
	payload = append(payload, myPub...)      // sender public key (32 bytes)
	payload = append(payload, mac...)
	payload = append(payload, ciphertext...)

	return EncodePacket(Packet{
		Route:        RouteFlood,
		Type:         PayloadAnonReq,
		PathHashSize: o.pathHashSize,
		Payload:      payload,
	})
}
