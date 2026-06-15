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
	// Shared16 is the X25519 shared secret for pairwise encrypted payloads
	// (REQ, RESPONSE, TXT_MSG, PATH), derived via Identity.SharedSecret. Pass
	// the FULL 32-byte secret: the firmware uses its first 16 bytes as the
	// AES-128 key and all 32 bytes as the HMAC key. (Name kept for
	// compatibility; a 16-byte value decrypts but fails MAC against firmware.)
	Shared16 []byte

	// ChannelSecret is the 16-byte channel PSK for GRP_TXT / GRP_DATA.
	ChannelSecret []byte

	// Registry holds optional application-defined body decoders.
	Registry *Registry
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
		if len(ctx.Shared16) < cipherKeySize {
			return RawPayload{Type: pkt.Type, Raw: pkt.Payload}, nil
		}
		return DecodeDirectTextPayload(ctx.Shared16, pkt.Payload)

	case PayloadReq:
		if len(ctx.Shared16) < cipherKeySize {
			return RawPayload{Type: pkt.Type, Raw: pkt.Payload}, nil
		}
		req, err := DecodeReqPayload(ctx.Shared16, pkt.Payload)
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
		if len(ctx.Shared16) < cipherKeySize {
			return RawPayload{Type: pkt.Type, Raw: pkt.Payload}, nil
		}
		return DecodeResponsePayload(ctx.Shared16, pkt.Payload)

	case PayloadPath:
		if len(ctx.Shared16) < cipherKeySize {
			return RawPayload{Type: pkt.Type, Raw: pkt.Payload}, nil
		}
		return DecodePathPayload(ctx.Shared16, pkt.Payload)

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
		// ANON_REQ requires the recipient's private key — return raw if unavailable.
		return RawPayload{Type: pkt.Type, Raw: pkt.Payload}, nil

	case PayloadRawCustom:
		// RAW_CUSTOM is intentionally opaque; always raw pass-through.
		return RawPayload{Type: pkt.Type, Raw: pkt.Payload}, nil

	default:
		return RawPayload{Type: pkt.Type, Raw: pkt.Payload}, nil
	}
}
