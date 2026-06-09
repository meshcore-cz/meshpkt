package meshpkt

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// All of REQ, RESPONSE, PATH, and TXT_MSG share the same outer envelope:
//
//	[dest_hash:1][src_hash:1][mac:2][ciphertext]
//
// openEncryptedEnvelope decrypts this common envelope and returns the
// dest/src hashes and plaintext bytes.
func openEncryptedEnvelope(shared16, payload []byte, typeName string) (destHash, srcHash byte, plaintext []byte, err error) {
	if len(shared16) < cipherKeySize {
		return 0, 0, nil, fmt.Errorf("meshpkt: shared secret too short")
	}
	if len(payload) < 2+cipherMACSize {
		return 0, 0, nil, fmt.Errorf("meshpkt: %s payload too short (%d bytes)", typeName, len(payload))
	}
	destHash = payload[0]
	srcHash = payload[1]
	mac := payload[2:4]
	ciphertext := payload[4:]
	var ok bool
	plaintext, ok, err = openMAC(shared16[:cipherKeySize], mac, ciphertext)
	if err != nil {
		return 0, 0, nil, fmt.Errorf("meshpkt: %s decrypt: %w", typeName, err)
	}
	if !ok {
		return 0, 0, nil, fmt.Errorf("meshpkt: %s MAC verification failed — wrong shared secret?", typeName)
	}
	return destHash, srcHash, plaintext, nil
}

// sealEncryptedEnvelope encrypts plaintext and builds the [dest][src][mac][ct] payload.
func sealEncryptedEnvelope(shared16 []byte, destHash, srcHash byte, plaintext []byte) ([]byte, error) {
	mac, ciphertext, err := sealMAC(shared16[:cipherKeySize], plaintext)
	if err != nil {
		return nil, err
	}
	payload := make([]byte, 0, 2+cipherMACSize+len(ciphertext))
	payload = append(payload, destHash, srcHash)
	payload = append(payload, mac...)
	payload = append(payload, ciphertext...)
	return payload, nil
}

// ── REQ ──────────────────────────────────────────────────────────────────────

// Req holds the decoded content of a REQ payload.
// Wire plaintext: [timestamp:4 LE][request_data...]
// For BaseChatMesh, request_data[0] is the request type (0x01=get_stats, 0x02=keepalive).
type Req struct {
	DestHash  byte
	SrcHash   byte
	Timestamp time.Time
	ReqType   byte   // first byte of request data (0 if data is empty)
	Data      []byte // full request body after timestamp
}

// DecodeReqPayload decodes a REQ payload using the 16-byte shared secret.
func DecodeReqPayload(shared16, payload []byte) (Req, error) {
	destHash, srcHash, plain, err := openEncryptedEnvelope(shared16, payload, "REQ")
	if err != nil {
		return Req{}, err
	}
	if len(plain) < 4 {
		return Req{}, fmt.Errorf("meshpkt: REQ plaintext too short (%d bytes)", len(plain))
	}
	ts := time.Unix(int64(binary.LittleEndian.Uint32(plain[0:4])), 0)
	data := plain[4:]
	var reqType byte
	if len(data) > 0 {
		reqType = data[0]
	}
	return Req{
		DestHash:  destHash,
		SrcHash:   srcHash,
		Timestamp: ts,
		ReqType:   reqType,
		Data:      data,
	}, nil
}

// DecodeReqPayloadFromKeys derives the shared secret from hex keys and decodes a REQ payload.
func DecodeReqPayloadFromKeys(payload []byte, privHex, peerPubHex string) (Req, error) {
	shared, _, _, err := keysAndSecret(privHex, peerPubHex)
	if err != nil {
		return Req{}, err
	}
	return DecodeReqPayload(shared[:cipherKeySize], payload)
}

// ReqPacket builds a complete REQ packet.
// reqType is the request type byte (0x01=get_stats, 0x02=keepalive, etc.).
// data is the additional request body (may be empty).
func ReqPacket(shared16 []byte, destHash, srcHash byte, reqType byte, data []byte, opts ...Option) ([]byte, error) {
	o := &packetOptions{pathHashSize: defaultPathHashSize}
	for _, opt := range opts {
		opt(o)
	}
	ts := time.Now()
	plain := make([]byte, 5+len(data))
	binary.LittleEndian.PutUint32(plain[0:4], uint32(ts.Unix()))
	plain[4] = reqType
	copy(plain[5:], data)
	payload, err := sealEncryptedEnvelope(shared16, destHash, srcHash, plain)
	if err != nil {
		return nil, fmt.Errorf("meshpkt: REQ encrypt: %w", err)
	}
	return EncodePacket(Packet{
		Route:        RouteFlood,
		Type:         PayloadReq,
		PathHashSize: o.pathHashSize,
		Payload:      payload,
	})
}

// ReqPacketFromKeys performs X25519 ECDH and builds a REQ packet.
func ReqPacketFromKeys(privHex, peerPubHex string, reqType byte, data []byte, opts ...Option) ([]byte, error) {
	shared, myPub, peerPub, err := keysAndSecret(privHex, peerPubHex)
	if err != nil {
		return nil, err
	}
	return ReqPacket(shared[:cipherKeySize], peerPub[0], myPub[0], reqType, data, opts...)
}

// ── RESPONSE ─────────────────────────────────────────────────────────────────

// Response holds the decoded content of a RESPONSE payload.
// Wire plaintext: opaque application-defined response body.
type Response struct {
	DestHash byte
	SrcHash  byte
	Data     []byte // decrypted response body (application-defined)
}

// DecodeResponsePayload decodes a RESPONSE payload using the 16-byte shared secret.
func DecodeResponsePayload(shared16, payload []byte) (Response, error) {
	destHash, srcHash, plain, err := openEncryptedEnvelope(shared16, payload, "RESPONSE")
	if err != nil {
		return Response{}, err
	}
	return Response{DestHash: destHash, SrcHash: srcHash, Data: plain}, nil
}

// DecodeResponsePayloadFromKeys derives the shared secret and decodes a RESPONSE payload.
func DecodeResponsePayloadFromKeys(payload []byte, privHex, peerPubHex string) (Response, error) {
	shared, _, _, err := keysAndSecret(privHex, peerPubHex)
	if err != nil {
		return Response{}, err
	}
	return DecodeResponsePayload(shared[:cipherKeySize], payload)
}

// ── PATH ─────────────────────────────────────────────────────────────────────

// ReturnedPath holds the decoded content of a PATH payload.
// Wire plaintext: [path_len:1][path...][extra_type:1][extra...]
// The path field contains 1-byte node hashes for intermediate hops.
type ReturnedPath struct {
	DestHash  byte
	SrcHash   byte
	Path      []byte // hop node hashes (1 byte each)
	ExtraType byte   // bundled extra payload type (0 = none)
	Extra     []byte // bundled extra payload (may be empty)
}

// PathHashes returns the individual hop hashes from the path.
func (p ReturnedPath) PathHashes() []string {
	hashes := make([]string, len(p.Path))
	for i, b := range p.Path {
		hashes[i] = fmt.Sprintf("%02x", b)
	}
	return hashes
}

// DecodePathPayload decodes a PATH payload using the 16-byte shared secret.
func DecodePathPayload(shared16, payload []byte) (ReturnedPath, error) {
	destHash, srcHash, plain, err := openEncryptedEnvelope(shared16, payload, "PATH")
	if err != nil {
		return ReturnedPath{}, err
	}
	if len(plain) < 1 {
		return ReturnedPath{}, fmt.Errorf("meshpkt: PATH plaintext too short")
	}
	pathLen := int(plain[0])
	off := 1
	if off+pathLen > len(plain) {
		pathLen = len(plain) - off // tolerate truncation
	}
	path := make([]byte, pathLen)
	copy(path, plain[off:off+pathLen])
	off += pathLen

	var extraType byte
	var extra []byte
	if off < len(plain) {
		extraType = plain[off]
		off++
		if off < len(plain) {
			extra = plain[off:]
		}
	}
	return ReturnedPath{
		DestHash:  destHash,
		SrcHash:   srcHash,
		Path:      path,
		ExtraType: extraType,
		Extra:     extra,
	}, nil
}

// DecodePathPayloadFromKeys derives the shared secret and decodes a PATH payload.
func DecodePathPayloadFromKeys(payload []byte, privHex, peerPubHex string) (ReturnedPath, error) {
	shared, _, _, err := keysAndSecret(privHex, peerPubHex)
	if err != nil {
		return ReturnedPath{}, err
	}
	return DecodePathPayload(shared[:cipherKeySize], payload)
}

// ── helpers ──────────────────────────────────────────────────────────────────

// trimNul removes a trailing NUL byte and surrounding whitespace.
func trimNul(s string) string {
	if idx := strings.IndexByte(s, 0); idx >= 0 {
		s = s[:idx]
	}
	return strings.TrimSpace(s)
}

// hexBytes returns a hex string for a byte slice (empty → "").
func hexBytes(b []byte) string { return hex.EncodeToString(b) }
