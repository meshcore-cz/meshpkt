package meshpkt

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"fmt"

	"filippo.io/edwards25519"
)

// Identity is a firmware-compatible Ed25519 node identity.
//
// MeshCore nodes sign their ADVERT payloads with Ed25519 and derive shared
// secrets for message encryption via Ed25519-to-X25519 key conversion
// (matching firmware's Identity::calcSharedSecret / ed25519_key_exchange).
//
// Store Seed (the 32-byte seed) to persist and restore the identity.
type Identity struct {
	PublicKey  [32]byte // Ed25519 public key — embed in Advert.PublicKey
	PrivateKey [64]byte // Ed25519 private key (seed ‖ public key)
	Seed       [32]byte // 32-byte canonical seed for storage
}

// GenerateIdentity creates a fresh Ed25519 node identity.
func GenerateIdentity() (Identity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Identity{}, fmt.Errorf("meshpkt: generate identity: %w", err)
	}
	var id Identity
	copy(id.PublicKey[:], pub)
	copy(id.PrivateKey[:], priv)
	copy(id.Seed[:], priv.Seed())
	return id, nil
}

// IdentityFromSeed restores an Ed25519 identity from its 32-byte seed.
func IdentityFromSeed(seed [32]byte) (Identity, error) {
	priv := ed25519.NewKeyFromSeed(seed[:])
	var id Identity
	copy(id.PublicKey[:], priv.Public().(ed25519.PublicKey))
	copy(id.PrivateKey[:], priv)
	id.Seed = seed
	return id, nil
}

// Sign signs message with the Ed25519 identity and returns the 64-byte signature.
func (id Identity) Sign(message []byte) [64]byte {
	priv := ed25519.PrivateKey(id.PrivateKey[:])
	sig := ed25519.Sign(priv, message)
	var out [64]byte
	copy(out[:], sig)
	return out
}

// Verify reports whether signature is a valid Ed25519 signature over message
// by the key publicKey.
func Verify(publicKey [32]byte, message []byte, signature [64]byte) bool {
	return ed25519.Verify(ed25519.PublicKey(publicKey[:]), message, signature[:])
}

// SharedSecret derives a 32-byte shared secret compatible with firmware's
// Identity::calcSharedSecret / ed25519_key_exchange. Both nodes must use
// the same derivation so alice.SharedSecret(bob.PublicKey) ==
// bob.SharedSecret(alice.PublicKey).
//
// Derivation:
//  1. Convert peerPublicKey (Edwards25519) to Montgomery-form X25519 public key.
//  2. Derive our X25519 scalar: SHA-512(seed)[0:32] with standard bit clamping.
//  3. Return X25519(scalar, montgomery_peer).
func (id Identity) SharedSecret(peerPublicKey [32]byte) ([32]byte, error) {
	// Derive X25519 private scalar from our Ed25519 seed.
	h := sha512.Sum512(id.Seed[:])
	return sharedSecretFromScalar(h[:32], peerPublicKey[:])
}

// SharedSecretFromExpanded derives the firmware-compatible shared secret from an
// orlp/ed25519 expanded private key — SHA-512(seed), as exported by MeshCore
// companion apps ("Export Private Key") — and a peer's Ed25519 public key.
//
// MeshCore companions export the 64-byte expanded private key, not the 32-byte
// seed. Its first 32 bytes are the X25519 scalar (matching SHA-512(seed)[:32]),
// so this derives the same secret as Identity.SharedSecret without needing the
// seed. expandedPriv may be 64 bytes (full expanded key) or 32 bytes (just the
// scalar); only the first 32 bytes are used. peerPublicKey is the peer's 32-byte
// Ed25519 public key (as carried in their ADVERT).
func SharedSecretFromExpanded(expandedPriv, peerPublicKey []byte) ([32]byte, error) {
	if len(expandedPriv) != 32 && len(expandedPriv) != 64 {
		return [32]byte{}, fmt.Errorf("meshpkt: expanded private key must be 32 or 64 bytes, got %d", len(expandedPriv))
	}
	if len(peerPublicKey) != 32 {
		return [32]byte{}, fmt.Errorf("meshpkt: peer public key must be 32 bytes, got %d", len(peerPublicKey))
	}
	return sharedSecretFromScalar(expandedPriv[:32], peerPublicKey)
}

// identitySharedSecret derives the firmware-compatible shared secret from a hex
// 32-byte identity seed and a hex 32-byte peer Ed25519 public key. It is the
// seed-input counterpart of SharedSecretFromExpanded (which takes the already
// SHA-512-expanded private key) and underpins the *FromIdentity decoders.
func identitySharedSecret(seedHex, peerEdPubHex string) ([32]byte, error) {
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		return [32]byte{}, fmt.Errorf("meshpkt: invalid seed: %w", err)
	}
	if len(seed) != 32 {
		return [32]byte{}, fmt.Errorf("meshpkt: seed must be 32 bytes, got %d", len(seed))
	}
	peer, err := hex.DecodeString(peerEdPubHex)
	if err != nil {
		return [32]byte{}, fmt.Errorf("meshpkt: invalid peer public key: %w", err)
	}
	if len(peer) != 32 {
		return [32]byte{}, fmt.Errorf("meshpkt: peer public key must be 32 bytes, got %d", len(peer))
	}
	var s, p [32]byte
	copy(s[:], seed)
	copy(p[:], peer)
	id, err := IdentityFromSeed(s)
	if err != nil {
		return [32]byte{}, err
	}
	return id.SharedSecret(p)
}

// sharedSecretFromScalar converts a peer Ed25519 public key to Montgomery form
// and performs X25519 ECDH using scalarSeed (a 32-byte value clamped per the
// standard bit-masking) as the private scalar.
func sharedSecretFromScalar(scalarSeed, peerPublicKey []byte) ([32]byte, error) {
	// Convert peer Ed25519 public key (Edwards) → X25519 (Montgomery).
	edPoint, err := new(edwards25519.Point).SetBytes(peerPublicKey)
	if err != nil {
		return [32]byte{}, fmt.Errorf("meshpkt: invalid peer public key: %w", err)
	}
	peerMontgomery := edPoint.BytesMontgomery()

	scalar := make([]byte, 32)
	copy(scalar, scalarSeed)
	scalar[0] &= 248
	scalar[31] &= 127
	scalar[31] |= 64

	curve := ecdh.X25519()
	priv, err := curve.NewPrivateKey(scalar)
	if err != nil {
		return [32]byte{}, fmt.Errorf("meshpkt: scalar to X25519 private key: %w", err)
	}
	pub, err := curve.NewPublicKey(peerMontgomery)
	if err != nil {
		return [32]byte{}, fmt.Errorf("meshpkt: peer Montgomery key: %w", err)
	}
	shared, err := priv.ECDH(pub)
	if err != nil {
		return [32]byte{}, fmt.Errorf("meshpkt: X25519 ECDH: %w", err)
	}
	return [32]byte(shared), nil
}

// ── Legacy X25519 API ─────────────────────────────────────────────────────────
// The functions below use native X25519 keypairs, not firmware-compatible
// Ed25519 identities. They remain for internal use by the direct-message,
// REQ, RESPONSE, and ANON_REQ helpers that rely on hex-encoded key pairs.
// Do not use these as MeshCore node identities.

// KeyPair holds a native X25519 identity keypair (not a MeshCore Ed25519 identity).
type KeyPair struct {
	// PublicKey is the hex-encoded 32-byte X25519 public key.
	PublicKey string
	// PrivateKey is the hex-encoded 32-byte X25519 private scalar.
	PrivateKey string
}

// Generate creates a fresh random X25519 keypair.
// Note: this is NOT a firmware-compatible identity. Use GenerateIdentity
// for MeshCore node identities. This function exists for use with the
// direct-message and request helpers that accept hex key strings.
func Generate() (KeyPair, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return KeyPair{}, fmt.Errorf("meshpkt: generate: %w", err)
	}
	return KeyPair{
		PublicKey:  hex.EncodeToString(priv.PublicKey().Bytes()),
		PrivateKey: hex.EncodeToString(priv.Bytes()),
	}, nil
}

// ParsePublicKey validates and decodes a hex-encoded 32-byte X25519 public key.
func ParsePublicKey(hexKey string) ([]byte, error) {
	b, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("meshpkt: invalid public key: %w", err)
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("meshpkt: public key must be 32 bytes, got %d", len(b))
	}
	if _, err := ecdh.X25519().NewPublicKey(b); err != nil {
		return nil, fmt.Errorf("meshpkt: invalid public key: %w", err)
	}
	return b, nil
}

// ParsePrivateKey validates and decodes a hex-encoded 32-byte X25519 private scalar.
func ParsePrivateKey(hexKey string) ([]byte, error) {
	b, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("meshpkt: invalid private key: %w", err)
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("meshpkt: private key must be 32 bytes, got %d", len(b))
	}
	if _, err := ecdh.X25519().NewPrivateKey(b); err != nil {
		return nil, fmt.Errorf("meshpkt: invalid private key: %w", err)
	}
	return b, nil
}

// PublicKeyFromPrivate derives the X25519 public key from a hex-encoded private scalar.
func PublicKeyFromPrivate(hexPriv string) (string, error) {
	b, err := ParsePrivateKey(hexPriv)
	if err != nil {
		return "", err
	}
	priv, err := ecdh.X25519().NewPrivateKey(b)
	if err != nil {
		return "", fmt.Errorf("meshpkt: %w", err)
	}
	return hex.EncodeToString(priv.PublicKey().Bytes()), nil
}

// SharedSecret performs X25519 ECDH and returns the 32-byte shared secret.
// Callers typically use only the first 16 bytes as an AES-128 key.
//
// Note: this uses native X25519 keys (generated by Generate), not
// firmware-compatible Ed25519 identities. For on-air interoperability with
// real MeshCore nodes use Identity.SharedSecret instead.
func SharedSecret(privHex, pubHex string) ([]byte, error) {
	privBytes, err := ParsePrivateKey(privHex)
	if err != nil {
		return nil, err
	}
	pubBytes, err := ParsePublicKey(pubHex)
	if err != nil {
		return nil, err
	}
	curve := ecdh.X25519()
	priv, err := curve.NewPrivateKey(privBytes)
	if err != nil {
		return nil, fmt.Errorf("meshpkt: invalid private key: %w", err)
	}
	pub, err := curve.NewPublicKey(pubBytes)
	if err != nil {
		return nil, fmt.Errorf("meshpkt: invalid public key: %w", err)
	}
	shared, err := priv.ECDH(pub)
	if err != nil {
		return nil, fmt.Errorf("meshpkt: ECDH: %w", err)
	}
	return shared, nil
}
