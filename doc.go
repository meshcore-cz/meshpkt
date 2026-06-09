// Package meshpkt encodes and decodes MeshCore radio packet wire formats.
//
// It is deliberately import-pure (stdlib crypto/* and encoding/* only) so
// the package compiles under GOOS=js GOARCH=wasm without modification.
//
// The full wire format (from docs/packet_format.md):
//
//	[header:1][transport_codes:0 or 4][path_len:1][path][payload]
//
// header byte layout (0bVVPPPPRR):
//
//	bits 1-0  route type  (RouteType)
//	bits 5-2  payload type (PayloadType)
//	bits 7-6  payload version (0–3)
//
// path_len byte layout (0bSSHHHHHH):
//
//	bits 5-0  hop count (0–63)
//	bits 7-6  path hash size − 1  → size = (byte >> 6) + 1
//
// transport_codes (2 × uint16 LE, 4 bytes total) are present only when route
// type is RouteTransportFlood or RouteTransportDirect.
//
// Payload formats:
//   - GRP_TXT:  [channel_hash:1][mac:2][AES-128-ECB ciphertext]
//   - TXT_MSG:  [dest_hash:1][src_hash:1][mac:2][AES-128-ECB ciphertext]
//   - ADVERT:   [pubkey:32][ts:4 LE][sig:64][appdata...]  (unencrypted)
//
// Plaintext inside encrypted payloads:
//
//	[timestamp:4 LE][flags:1][text]
//	flags = (txt_type << 2) | attempt
//
// Encryption: AES-128-ECB (zero-padded) + HMAC-SHA256(key32, ciphertext)[:2]
// where key32 = secret16 ‖ zero16.
//
// File layout:
//
//	doc.go      — this package overview
//	packet.go   — envelope encode/decode, RouteType, PayloadType, Packet, Option
//	crypto.go   — AES-128-ECB, HMAC-SHA256, sealMAC/openMAC (unexported)
//	keys.go     — X25519 keypair generation and ECDH
//	channel.go  — channel secret derivation and routing hash
//	grptxt.go   — GRP_TXT (channel text) codec
//	grpdata.go  — GRP_DATA (group datagram) codec
//	txtmsg.go   — TXT_MSG (direct text) codec
//	req.go      — REQ / RESPONSE / PATH codecs and shared encrypted envelope
//	anonreq.go  — ANON_REQ codec
//	advert.go   — ADVERT codec
//	ack.go      — ACK codec
//	control.go  — CONTROL / DISCOVER codecs
//	ops.go      — Op registry consumed by binding layers
//	call.go     — Call / CallJSON dispatch over the Op registry
//	examples.go — hardware-captured packet test vectors
package meshpkt
