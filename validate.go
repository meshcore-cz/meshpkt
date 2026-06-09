package meshpkt

import "errors"

// ValidateWire checks that pkt is a well-formed MeshCore wire frame.
// It enforces the byte-level invariants that firmware checks on every
// received packet regardless of payload type.
//
// Returns nil for a valid frame. All errors are sentinel values so
// callers can use errors.Is.
func ValidateWire(pkt Packet) error {
	if pkt.Version != CurrentPayloadVer {
		return ErrUnsupportedVersion
	}
	if pkt.Route > RouteTransportDirect {
		return ErrInvalidRoute
	}
	if pkt.Type > 0x0f {
		return ErrInvalidPayloadType
	}
	if pkt.PathHashSize < 1 || pkt.PathHashSize > 3 {
		return ErrInvalidPathHashSize
	}
	if len(pkt.Path)%pkt.PathHashSize != 0 {
		return ErrUnalignedPath
	}
	if len(pkt.Path) > MaxPathBytes {
		return ErrPathTooLong
	}
	if len(pkt.Payload) > MaxPayloadBytes {
		return ErrPayloadTooLong
	}
	if pkt.HopCount() > MaxHopCount {
		return ErrTooManyHops
	}
	return nil
}

// Firmware-semantics errors returned by ValidateFirmwareSemantics.
var (
	ErrTraceMustBeDirect      = errors.New("meshpkt: TRACE packet must use DIRECT route")
	ErrInvalidTraceOuterPath  = errors.New("meshpkt: TRACE outer path must use 1-byte hashes (SNR accumulator)")
	ErrUnalignedTraceRoute    = errors.New("meshpkt: TRACE route data length not aligned to hash width")
	ErrMultipartInnerType     = errors.New("meshpkt: MULTIPART currently only wraps ACK payloads")
	ErrMultipartRemainingBits = errors.New("meshpkt: MULTIPART remaining value exceeds 4 bits")
)

// ValidateFirmwareSemantics checks payload-type-specific rules that the
// MeshCore firmware enforces beyond raw wire validity. A packet may pass
// ValidateWire while failing ValidateFirmwareSemantics — for example a
// TRACE packet sent with a flood route is structurally valid but firmware
// will not process it.
//
// Call ValidateWire first; this function does not repeat those checks.
func ValidateFirmwareSemantics(pkt Packet) error {
	switch pkt.Type {
	case PayloadTrace:
		return validateTraceSemantics(pkt)
	case PayloadMultipart:
		return validateMultipartSemantics(pkt)
	}
	return nil
}

func validateTraceSemantics(pkt Packet) error {
	if pkt.Route != RouteDirect {
		return ErrTraceMustBeDirect
	}
	if pkt.PathHashSize != 1 {
		return ErrInvalidTraceOuterPath
	}
	if len(pkt.Payload) < 9 {
		return nil // too short to decode route data — leave to payload decoder
	}
	flags := pkt.Payload[8]
	width := 1 << (flags & 0x03)
	routeData := pkt.Payload[9:]
	if len(routeData)%width != 0 {
		return ErrUnalignedTraceRoute
	}
	return nil
}

func validateMultipartSemantics(pkt Packet) error {
	if len(pkt.Payload) < 1 {
		return nil
	}
	descriptor := pkt.Payload[0]
	remaining := descriptor >> 4
	innerType := PayloadType(descriptor & 0x0F)
	_ = remaining
	if innerType != PayloadAck {
		return ErrMultipartInnerType
	}
	return nil
}
