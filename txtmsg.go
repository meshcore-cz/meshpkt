package meshpkt

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// DirectText holds the decoded content of a TXT_MSG (direct text) message.
type DirectText struct {
	DestHash  byte // first byte of recipient's public key
	SrcHash   byte // first byte of sender's public key
	Timestamp time.Time
	TxtType   byte // upper 6 bits of flags byte (0 = plain text)
	Attempt   byte // lower 2 bits of flags byte
	Text      string
}

// DirectTextPacket builds a flooded TXT_MSG wire packet encrypted with the
// given 16-byte shared secret (derived from X25519 ECDH — see meshpkt.SharedSecret).
//
// destHash and srcHash are the first bytes of the recipient's and sender's
// public keys respectively, used for lightweight routing.
//
// Note: on-air interoperability with real MeshCore devices requires the shared
// secret to be derived the same way as the firmware (Ed25519 keys converted to
// Montgomery form then X25519 ECDH); meshpkt.SharedSecret performs this derivation.
// Cross-check against firmware Identity::calcSharedSecret before relying on it.
func DirectTextPacket(shared16 []byte, destHash, srcHash byte, text string, ts time.Time, txtType, attempt byte, opts ...Option) ([]byte, error) {
	o := &packetOptions{pathHashSize: defaultPathHashSize}
	for _, opt := range opts {
		opt(o)
	}
	if o.pathHashSize < 1 || o.pathHashSize > 3 {
		return nil, fmt.Errorf("meshpkt: unsupported path hash size %d (use 1–3)", o.pathHashSize)
	}
	if len(shared16) < cipherKeySize {
		return nil, fmt.Errorf("meshpkt: shared secret too short (%d bytes, need %d)", len(shared16), cipherKeySize)
	}
	if ts.IsZero() {
		ts = time.Now()
	}
	flags := (txtType << 2) | (attempt & 0x03)
	plaintext := buildDirectTextPlaintext(text, flags, ts)
	payload, err := buildDirectTextPayload(shared16, destHash, srcHash, plaintext)
	if err != nil {
		return nil, err
	}
	return EncodePacket(Packet{
		Route:        RouteFlood,
		Type:         PayloadTxtMsg,
		PathHashSize: o.pathHashSize,
		Payload:      payload,
	})
}

// DecodeDirectTextPayload decodes a TXT_MSG payload using the given 16-byte
// shared secret. Returns an error if the MAC is wrong or the payload is
// malformed.
//
// payload is the Payload field of a Packet returned by DecodePacket.
func DecodeDirectTextPayload(shared16, payload []byte) (DirectText, error) {
	if len(shared16) < cipherKeySize {
		return DirectText{}, fmt.Errorf("meshpkt: shared secret too short")
	}
	// payload = [dest_hash:1][src_hash:1][mac:2][ciphertext]
	if len(payload) < 2+cipherMACSize+cipherKeySize {
		return DirectText{}, fmt.Errorf("meshpkt: TXT_MSG payload too short (%d bytes)", len(payload))
	}
	destHash := payload[0]
	srcHash := payload[1]
	mac := payload[2:4]
	ciphertext := payload[4:]
	plaintext, ok, err := openMAC(shared16, mac, ciphertext)
	if err != nil {
		return DirectText{}, fmt.Errorf("meshpkt: TXT_MSG decrypt: %w", err)
	}
	if !ok {
		return DirectText{}, fmt.Errorf("meshpkt: TXT_MSG MAC verification failed — wrong shared secret?")
	}
	return parseDirectTextPlaintext(destHash, srcHash, plaintext)
}

// DirectTextPacketFromKeys performs X25519 ECDH using privHex and peerPubHex,
// derives dest/src hashes from the public keys (first byte of each), and
// encodes the TXT_MSG packet. This is a convenience wrapper that removes the
// need to call SharedSecret and ParsePublicKey separately.
func DirectTextPacketFromKeys(privHex, peerPubHex, text string, ts time.Time, opts ...Option) ([]byte, error) {
	shared, myPub, peerPub, err := keysAndSecret(privHex, peerPubHex)
	if err != nil {
		return nil, err
	}
	return DirectTextPacket(shared, peerPub[0], myPub[0], text, ts, 0, 0, opts...)
}

// DirectTextPacketFromIdentity builds a flooded TXT_MSG packet addressed to peerPub, encrypted with
// the FIRMWARE-COMPATIBLE shared secret derived from our Ed25519 identity (Identity.SharedSecret:
// SHA-512(seed)[:32] clamp → ed→Montgomery → X25519). Unlike DirectTextPacketFromKeys (which uses
// the legacy native-X25519 keypair path), this interoperates with real MeshCore nodes. dest/src
// hashes are the first byte of the recipient's and our public keys.
func DirectTextPacketFromIdentity(seed [32]byte, peerPub [32]byte, text string, ts time.Time, attempt byte, opts ...Option) ([]byte, error) {
	id, err := IdentityFromSeed(seed)
	if err != nil {
		return nil, fmt.Errorf("meshpkt: identity from seed: %w", err)
	}
	shared, err := id.SharedSecret(peerPub)
	if err != nil {
		return nil, err
	}
	return DirectTextPacket(shared[:], peerPub[0], id.PublicKey[0], text, ts, 0, attempt, opts...)
}

// DecodeDirectTextPayloadFromExpanded decodes a TXT_MSG payload using the
// FIRMWARE-COMPATIBLE shared secret derived from an orlp/ed25519 expanded private
// key (SHA-512(seed), as exported by MeshCore companion apps) and the peer's
// Ed25519 public key. Unlike DecodeDirectTextPayloadFromKeys (legacy native
// X25519), this interoperates with real MeshCore nodes. expandedPrivHex may be
// 64 bytes (full expanded key) or 32 bytes (scalar); peerEdPubHex is the peer's
// 32-byte Ed25519 public key from their ADVERT.
func DecodeDirectTextPayloadFromExpanded(payload []byte, expandedPrivHex, peerEdPubHex string) (DirectText, error) {
	priv, err := hex.DecodeString(expandedPrivHex)
	if err != nil {
		return DirectText{}, fmt.Errorf("meshpkt: invalid private key: %w", err)
	}
	peer, err := hex.DecodeString(peerEdPubHex)
	if err != nil {
		return DirectText{}, fmt.Errorf("meshpkt: invalid peer public key: %w", err)
	}
	shared, err := SharedSecretFromExpanded(priv, peer)
	if err != nil {
		return DirectText{}, err
	}
	return DecodeDirectTextPayload(shared[:], payload)
}

// DecodeDirectTextPayloadFromKeys performs X25519 ECDH using privHex and
// peerPubHex to recover the shared secret, then decodes the TXT_MSG payload.
func DecodeDirectTextPayloadFromKeys(payload []byte, privHex, peerPubHex string) (DirectText, error) {
	shared, _, _, err := keysAndSecret(privHex, peerPubHex)
	if err != nil {
		return DirectText{}, err
	}
	return DecodeDirectTextPayload(shared, payload)
}

// keysAndSecret is the shared helper: parses both keys, runs ECDH, and returns
// the 32-byte shared secret along with the raw public key bytes.
func keysAndSecret(privHex, peerPubHex string) (shared, myPub, peerPub []byte, err error) {
	myPubHex, err := PublicKeyFromPrivate(privHex)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("meshpkt: derive public key: %w", err)
	}
	myPub, err = ParsePublicKey(myPubHex)
	if err != nil {
		return nil, nil, nil, err
	}
	peerPub, err = ParsePublicKey(peerPubHex)
	if err != nil {
		return nil, nil, nil, err
	}
	shared, err = SharedSecret(privHex, peerPubHex)
	if err != nil {
		return nil, nil, nil, err
	}
	return shared, myPub, peerPub, nil
}

func buildDirectTextPlaintext(text string, flags byte, ts time.Time) []byte {
	buf := make([]byte, 5+len(text))
	binary.LittleEndian.PutUint32(buf[0:4], uint32(ts.Unix()))
	buf[4] = flags
	copy(buf[5:], text)
	return buf
}

func buildDirectTextPayload(key16 []byte, destHash, srcHash byte, plaintext []byte) ([]byte, error) {
	mac, ciphertext, err := sealMAC(key16, plaintext)
	if err != nil {
		return nil, err
	}
	payload := make([]byte, 0, 2+cipherMACSize+len(ciphertext))
	payload = append(payload, destHash, srcHash)
	payload = append(payload, mac...)
	payload = append(payload, ciphertext...)
	return payload, nil
}

func parseDirectTextPlaintext(destHash, srcHash byte, plain []byte) (DirectText, error) {
	if len(plain) < 5 {
		return DirectText{}, fmt.Errorf("meshpkt: TXT_MSG plaintext too short (%d bytes)", len(plain))
	}
	tsUnix := int64(binary.LittleEndian.Uint32(plain[0:4]))
	flags := plain[4]
	text := strings.TrimRight(string(plain[5:]), "\x00")
	return DirectText{
		DestHash:  destHash,
		SrcHash:   srcHash,
		Timestamp: time.Unix(tsUnix, 0),
		TxtType:   flags >> 2,
		Attempt:   flags & 0x03,
		Text:      text,
	}, nil
}
