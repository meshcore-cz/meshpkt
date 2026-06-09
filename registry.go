package meshpkt

import "fmt"

// BodyDecoder decodes an opaque body from a typed payload envelope.
// The []byte argument is the decrypted or raw body content after any
// envelope header fields have been stripped.
type BodyDecoder func([]byte) (any, error)

// Registry holds application-defined decoders for opaque payload bodies.
// Ship built-in helpers for known firmware messages while always preserving
// undecoded bytes; extend without forking by registering custom decoders.
//
// All map keys are optional — nil entries fall back to raw pass-through.
type Registry struct {
	// RequestDecoders maps REQ request-type byte (data[0]) to a decoder.
	RequestDecoders map[byte]BodyDecoder

	// ResponseDecoders maps RESPONSE sub-type byte to a decoder.
	ResponseDecoders map[byte]BodyDecoder

	// ControlDecoders maps CONTROL sub-type nibble to a decoder.
	ControlDecoders map[byte]BodyDecoder

	// CustomDecoders maps RAW_CUSTOM application tag (hex of first byte) to a decoder.
	CustomDecoders map[string]BodyDecoder
}

// NewRegistry returns an empty Registry with all maps initialised.
func NewRegistry() *Registry {
	return &Registry{
		RequestDecoders:  make(map[byte]BodyDecoder),
		ResponseDecoders: make(map[byte]BodyDecoder),
		ControlDecoders:  make(map[byte]BodyDecoder),
		CustomDecoders:   make(map[string]BodyDecoder),
	}
}

// RawPayload wraps undecoded payload bytes. Returned by DecodePayload when
// no decoder is registered or for intentionally opaque payload types.
type RawPayload struct {
	Type PayloadType
	Raw  []byte
}

// DecodeContext carries shared secrets and identity material needed by
// the typed payload decoders.
type DecodeContext struct {
	// Identity is the local node's Ed25519 identity. When set together with
	// PeerPublicKey, the shared secret is derived automatically for TXT_MSG,
	// REQ, RESPONSE, and PATH payloads. For ANON_REQ, the shared secret is
	// derived from Identity and the sender's Ed25519 public key embedded in
	// the payload.
	Identity *Identity

	// PeerPublicKey is the peer's 32-byte Ed25519 public key, used together
	// with Identity to derive the shared secret when Shared16 is not provided.
	PeerPublicKey *[32]byte

	// Shared16 is the 16-byte AES-128 key for encrypted payloads (REQ,
	// RESPONSE, TXT_MSG, PATH). Takes precedence over Identity+PeerPublicKey
	// when set.
	Shared16 []byte

	// ChannelSecret is the 16-byte channel PSK for GRP_TXT / GRP_DATA.
	ChannelSecret []byte

	// Registry holds optional application-defined body decoders.
	Registry *Registry
}

// resolveShared16 returns the 16-byte key from ctx: Shared16 takes precedence;
// otherwise it is derived from Identity and PeerPublicKey.
func (ctx DecodeContext) resolveShared16() []byte {
	if len(ctx.Shared16) >= cipherKeySize {
		return ctx.Shared16[:cipherKeySize]
	}
	if ctx.Identity != nil && ctx.PeerPublicKey != nil {
		s, err := ctx.Identity.SharedSecret(*ctx.PeerPublicKey)
		if err == nil {
			return s[:cipherKeySize]
		}
	}
	return nil
}

// DecodePayload dispatches pkt.Payload to the appropriate typed decoder
// based on pkt.Type. Returns a typed value on success, or a RawPayload
// for intentionally opaque types (RAW_CUSTOM) and unknown reserved types.
//
// Returns an error only for types where decoding is possible but fails
// (e.g. bad signature, MAC mismatch, truncated required fields).
func DecodePayload(pkt Packet, ctx DecodeContext) (any, error) {
	switch pkt.Type {
	case PayloadAck:
		crc, err := DecodeAckPayload(pkt.Payload)
		if err != nil {
			return nil, err
		}
		return crc, nil

	case PayloadAdvert:
		return DecodeAdvertPayload(pkt.Payload)

	case PayloadGrpTxt:
		if len(ctx.ChannelSecret) < cipherKeySize {
			return RawPayload{Type: pkt.Type, Raw: pkt.Payload}, nil
		}
		return DecodeGroupTextPayload(ctx.ChannelSecret, pkt.Payload)

	case PayloadGrpData:
		if len(ctx.ChannelSecret) < cipherKeySize {
			return RawPayload{Type: pkt.Type, Raw: pkt.Payload}, nil
		}
		return DecodeGrpDataPayload(ctx.ChannelSecret, pkt.Payload)

	case PayloadTxtMsg:
		key := ctx.resolveShared16()
		if key == nil {
			return RawPayload{Type: pkt.Type, Raw: pkt.Payload}, nil
		}
		return DecodeDirectTextPayload(key, pkt.Payload)

	case PayloadReq:
		key := ctx.resolveShared16()
		if key == nil {
			return RawPayload{Type: pkt.Type, Raw: pkt.Payload}, nil
		}
		req, err := DecodeReqPayload(key, pkt.Payload)
		if err != nil {
			return nil, err
		}
		if ctx.Registry != nil && len(req.Data) > 0 {
			if dec, ok := ctx.Registry.RequestDecoders[req.ReqType]; ok {
				body, err := dec(req.Data)
				if err != nil {
					return nil, fmt.Errorf("REQ body decoder: %w", err)
				}
				return body, nil
			}
		}
		return req, nil

	case PayloadResponse:
		key := ctx.resolveShared16()
		if key == nil {
			return RawPayload{Type: pkt.Type, Raw: pkt.Payload}, nil
		}
		return DecodeResponsePayload(key, pkt.Payload)

	case PayloadPath:
		key := ctx.resolveShared16()
		if key == nil {
			return RawPayload{Type: pkt.Type, Raw: pkt.Payload}, nil
		}
		return DecodePathPayload(key, pkt.Payload)

	case PayloadTrace:
		return DecodeTracePayload(pkt.Payload)

	case PayloadMultipart:
		return DecodeMultipartPayload(pkt.Payload)

	case PayloadControl:
		c, err := DecodeControlPayload(pkt.Payload)
		if err != nil {
			return nil, err
		}
		if ctx.Registry != nil && c.DiscoverReq == nil && c.DiscoverResp == nil {
			if dec, ok := ctx.Registry.ControlDecoders[c.SubType]; ok {
				body, err := dec(c.Data)
				if err != nil {
					return nil, fmt.Errorf("CONTROL body decoder: %w", err)
				}
				return body, nil
			}
		}
		return c, nil

	case PayloadAnonReq:
		// Decode if an Identity is available; the sender's Ed25519 public key
		// is embedded in the payload so no PeerPublicKey is required.
		if ctx.Identity != nil {
			a, err := DecodeAnonReqPayload(pkt.Payload, *ctx.Identity)
			if err != nil {
				return nil, err
			}
			return a, nil
		}
		return RawPayload{Type: pkt.Type, Raw: pkt.Payload}, nil

	case PayloadRawCustom:
		return RawPayload{Type: pkt.Type, Raw: pkt.Payload}, nil

	default:
		return RawPayload{Type: pkt.Type, Raw: pkt.Payload}, nil
	}
}
