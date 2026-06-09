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
// The canonical persisted form is the 32-byte Seed. Store Seed (or its
// hex encoding via SeedHex) to persist and restore the identity.
type Identity struct {
	PublicKey [32]byte // Ed25519 public key — embed in Advert.PublicKey
	Seed      [32]byte // 32-byte canonical seed for storage
}

// GenerateIdentity creates a fresh Ed25519 node identity.
func GenerateIdentity() (Identity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Identity{}, fmt.Errorf("meshpkt: generate identity: %w", err)
	}
	var id Identity
	copy(id.PublicKey[:], pub)
	copy(id.Seed[:], priv.Seed())
	return id, nil
}

// IdentityFromSeed restores an Ed25519 identity from its 32-byte seed.
func IdentityFromSeed(seed [32]byte) (Identity, error) {
	priv := ed25519.NewKeyFromSeed(seed[:])
	var id Identity
	copy(id.PublicKey[:], priv.Public().(ed25519.PublicKey))
	id.Seed = seed
	return id, nil
}

// IdentityFromSeedHex restores an Ed25519 identity from a 64-character hex seed.
func IdentityFromSeedHex(seedHex string) (Identity, error) {
	b, err := hex.DecodeString(seedHex)
	if err != nil {
		return Identity{}, fmt.Errorf("meshpkt: invalid seed hex: %w", err)
	}
	if len(b) != 32 {
		return Identity{}, fmt.Errorf("meshpkt: seed must be 32 bytes, got %d", len(b))
	}
	return IdentityFromSeed([32]byte(b))
}

// ParseIdentityPublicKeyHex decodes a 64-character hex Ed25519 public key.
func ParseIdentityPublicKeyHex(pubHex string) ([32]byte, error) {
	b, err := hex.DecodeString(pubHex)
	if err != nil {
		return [32]byte{}, fmt.Errorf("meshpkt: invalid public key hex: %w", err)
	}
	if len(b) != 32 {
		return [32]byte{}, fmt.Errorf("meshpkt: public key must be 32 bytes, got %d", len(b))
	}
	return [32]byte(b), nil
}

// SeedHex returns the identity seed as a 64-character lowercase hex string.
func (id Identity) SeedHex() string {
	return hex.EncodeToString(id.Seed[:])
}

// PublicKeyHex returns the Ed25519 public key as a 64-character lowercase hex string.
func (id Identity) PublicKeyHex() string {
	return hex.EncodeToString(id.PublicKey[:])
}

// Sign signs message with the Ed25519 identity and returns the 64-byte signature.
// The private key is derived from Seed on each call and not stored.
func (id Identity) Sign(message []byte) [64]byte {
	priv := ed25519.NewKeyFromSeed(id.Seed[:])
	sig := ed25519.Sign(priv, message)
	var out [64]byte
	copy(out[:], sig)
	return out
}

// Verify reports whether signature is a valid Ed25519 signature over message
// by publicKey.
func Verify(publicKey [32]byte, message []byte, signature [64]byte) bool {
	return ed25519.Verify(ed25519.PublicKey(publicKey[:]), message, signature[:])
}

// SharedSecret derives a 32-byte shared secret compatible with firmware's
// Identity::calcSharedSecret / ed25519_key_exchange. Both nodes must use
// the same derivation so alice.SharedSecret(bob.PublicKey) ==
// bob.SharedSecret(alice.PublicKey).
//
// peerPublicKey is the peer's Ed25519 public key (not an X25519 key).
// The Ed25519→X25519 conversion is performed internally.
//
// Derivation:
//  1. Convert peerPublicKey (Edwards25519) to Montgomery-form X25519 public key.
//  2. Derive our X25519 scalar: SHA-512(seed)[0:32] with standard bit clamping.
//  3. Return X25519(scalar, montgomery_peer).
func (id Identity) SharedSecret(peerPublicKey [32]byte) ([32]byte, error) {
	// Convert peer Ed25519 public key (Edwards) → X25519 (Montgomery).
	edPoint, err := new(edwards25519.Point).SetBytes(peerPublicKey[:])
	if err != nil {
		return [32]byte{}, fmt.Errorf("meshpkt: invalid peer Ed25519 public key: %w", err)
	}
	peerMontgomery := edPoint.BytesMontgomery()

	// Derive X25519 private scalar from our Ed25519 seed.
	h := sha512.Sum512(id.Seed[:])
	scalar := make([]byte, 32)
	copy(scalar, h[:32])
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

// DeriveX25519 derives the firmware-compatible X25519 private scalar and its
// corresponding public key from an Ed25519 seed, using SHA-512(seed)[0:32]
// with standard bit-clamping. Useful for debugging and cross-checking against
// firmware. Identity.SharedSecret performs this derivation internally.
func DeriveX25519(seed [32]byte) (privHex, pubHex string, err error) {
	h := sha512.Sum512(seed[:])
	scalar := make([]byte, 32)
	copy(scalar, h[:32])
	scalar[0] &= 248
	scalar[31] &= 127
	scalar[31] |= 64
	curve := ecdh.X25519()
	priv, e := curve.NewPrivateKey(scalar)
	if e != nil {
		return "", "", fmt.Errorf("meshpkt: derive X25519: %w", e)
	}
	return hex.EncodeToString(scalar), hex.EncodeToString(priv.PublicKey().Bytes()), nil
}
