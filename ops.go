package meshpkt

import (
	"encoding/hex"
	"fmt"
	"time"
)

// ParamKind describes how an argument crosses an external binding boundary
// (e.g. JavaScript/WASM, HTTP, CLI).
type ParamKind int

const (
	ParamString ParamKind = iota // plain string
	ParamHex                     // hex-encoded bytes → binding decodes to []byte before Run
	ParamInt                     // integer
	ParamFloat                   // float64; binding passes JSON number / JS double
)

// Choice is a named integer value for a Param with Kind==ParamInt, rendered
// as a <select> option in UI.
type Choice struct {
	Value int
	Label string
}

// Param describes a single input argument of an Op.
type Param struct {
	Name string
	Kind ParamKind

	// UI metadata (used by code generators and form renderers).
	Label       string   // human-readable label; defaults to Name if empty
	Placeholder string   // input placeholder hint
	Optional    bool     // if true, empty/zero value is accepted without validation error
	Choices     []Choice // if non-nil, render as <select>; empty slice = number input
	ShowWhen    string   // name of a sibling ParamInt that gates visibility
	ShowValue   int      // show this param only when ShowWhen param value == ShowValue
	Group       string   // params sharing a non-empty Group name render side-by-side
	Action      string   // "keypair" → button fills with new private key; "keypair-pub" → public key
	Widget      string   // "checkbox" → render ParamInt as checkbox; "textarea" → use <textarea>
	AutoFill    string   // "payloadHex" → populate from decode context; hidden in form UI
	Secret      bool     // store in URL hash (not query string) for privacy
}

// ResultKind describes the TypeScript/JSON type of a result field.
type ResultKind int

const (
	ResultString      ResultKind = iota // → string
	ResultNumber                        // → number (int, float, unix timestamp)
	ResultBool                          // → boolean
	ResultStringArray                   // → string[]
	ResultNumberPair                    // → [number, number]
)

// ResultField describes a single field in the map[string]any returned by Op.Run.
type ResultField struct {
	Name     string
	Kind     ResultKind
	Optional bool
	Label    string // human-readable label for UI display; defaults to Name if empty
}

// Op describes a single callable operation. Binding layers (WASM, HTTP, CLI…)
// iterate Ops to build their dispatch tables automatically, and code generators
// use Params and Result to emit typed interfaces.
//
// Run receives pre-parsed arguments matching Params in order:
//   - ParamString → string
//   - ParamHex    → []byte (decoded by the binding layer)
//   - ParamInt    → int
//   - ParamFloat  → float64
//
// Result fields in the returned map use hex-encoded strings for byte slices so
// they cross any text boundary cleanly.
type Op struct {
	Name           string
	Params         []Param
	Result         []ResultField
	ResultTypeName string // friendly type name for code gen; defaults to pascal(Name)+"Result"

	// UI metadata (used by form renderers and code generators).
	Category      string // "encode" | "decode" | "key"
	Label         string // human-readable op name, e.g. "Encode channel message"
	TabGroup      string // groups ops into one UI tab; ops in same group show a variant toggle
	TabGroupLabel string // tab button title, e.g. "GRP_TXT"
	TabGroupSub   string // tab button subtitle, e.g. "channel message"
	TabGroupDoc   string // prose description of the packet type shown in UI help text
	TabLabel      string // variant selector label within a TabGroup, e.g. "By name"
	PacketType    string // for decode ops: the PayloadType.String() this op decodes, e.g. "GRP_TXT"

	Run func(args []any) (map[string]any, error)
}

// ── package-level choice helpers ──────────────────────────────────────────────

var allRouteChoices = func() []Choice {
	cs := make([]Choice, len(AllRouteTypes))
	for i, rt := range AllRouteTypes {
		cs[i] = Choice{Value: int(rt), Label: rt.String()}
	}
	return cs
}()

var allPayloadTypeChoices = func() []Choice {
	cs := make([]Choice, len(AllPayloadTypes))
	for i, pt := range AllPayloadTypes {
		cs[i] = Choice{Value: int(pt), Label: pt.String()}
	}
	return cs
}()

var hashSizeChoices = []Choice{{1, "1"}, {2, "2"}, {3, "3"}}

// Ops is the registry of all meshpkt operations exposed to binding layers.
var Ops = []Op{

	// ── encoders ──────────────────────────────────────────────────────────────

	{
		Name:          "encodeGroupText",
		Category:      "encode",
		Label:         "Encode channel message",
		TabGroup:      "grptxt",
		TabGroupLabel: "GRP_TXT",
		TabGroupSub:   "channel message",
		TabGroupDoc:   "A text message broadcast to everyone sharing a channel. Encrypted with AES-128-ECB plus a 2-byte HMAC-SHA256 tag, using a 16-byte key derived from the channel name — or supplied directly as a raw channel secret.",
		TabLabel:      "By name",
		Params: []Param{
			{Name: "channelName", Kind: ParamString, Label: "Channel name", Placeholder: "#test"},
			{Name: "sender", Kind: ParamString, Label: "Sender name", Placeholder: "Alice"},
			{Name: "text", Kind: ParamString, Label: "Message", Placeholder: "Hello mesh!", Widget: "textarea"},
		},
		Result:         []ResultField{{Name: "hex", Kind: ResultString, Label: "Hex packet"}},
		ResultTypeName: "HexResult",
		Run: func(args []any) (map[string]any, error) {
			pkt, err := GroupTextPacketFromName(args[0].(string), args[1].(string), args[2].(string), time.Now())
			if err != nil {
				return nil, err
			}
			return map[string]any{"hex": hex.EncodeToString(pkt)}, nil
		},
	},

	{
		Name:          "encodeGroupTextSecret",
		Category:      "encode",
		Label:         "Encode channel message (by secret)",
		TabGroup:      "grptxt",
		TabGroupLabel: "GRP_TXT",
		TabGroupSub:   "channel message",
		TabLabel:      "By secret",
		Params: []Param{
			{Name: "secret", Kind: ParamHex, Label: "Channel secret (16 bytes)", Placeholder: "32 hex chars", Secret: true},
			{Name: "sender", Kind: ParamString, Label: "Sender name", Placeholder: "Alice"},
			{Name: "text", Kind: ParamString, Label: "Message", Placeholder: "Hello mesh!", Widget: "textarea"},
		},
		Result: []ResultField{{Name: "hex", Kind: ResultString, Label: "Hex packet"}},
		Run: func(args []any) (map[string]any, error) {
			secret := args[0].([]byte)
			if len(secret) < ChannelSecretLen {
				return nil, fmt.Errorf("secret must be at least %d bytes", ChannelSecretLen)
			}
			pkt, err := GroupTextPacket(secret[:ChannelSecretLen], args[1].(string), args[2].(string), time.Now())
			if err != nil {
				return nil, err
			}
			return map[string]any{"hex": hex.EncodeToString(pkt)}, nil
		},
	},

	{
		Name:          "encodeGrpData",
		Category:      "encode",
		Label:         "Encode group datagram",
		TabGroup:      "grpdata",
		TabGroupLabel: "GRP_DATA",
		TabGroupSub:   "group datagram",
		TabGroupDoc:   "Arbitrary binary data broadcast on a channel, secured with the same channel encryption as GRP_TXT. Used for non-text payloads such as telemetry or app-specific data, tagged with a data-type byte.",
		TabLabel:      "By name",
		Params: []Param{
			{Name: "channelName", Kind: ParamString, Label: "Channel name", Placeholder: "#test"},
			{Name: "dataType", Kind: ParamInt, Label: "Data type", Placeholder: "0"},
			{Name: "data", Kind: ParamHex, Label: "Data (hex)", Optional: true, Widget: "textarea"},
		},
		Result:         []ResultField{{Name: "hex", Kind: ResultString, Label: "Hex packet"}},
		ResultTypeName: "HexResult",
		Run: func(args []any) (map[string]any, error) {
			pkt, err := GrpDataPacketFromName(args[0].(string), uint16(args[1].(int)), args[2].([]byte))
			if err != nil {
				return nil, err
			}
			return map[string]any{"hex": hex.EncodeToString(pkt)}, nil
		},
	},

	{
		Name:          "encodeGrpDataSecret",
		Category:      "encode",
		Label:         "Encode group datagram (by secret)",
		TabGroup:      "grpdata",
		TabGroupLabel: "GRP_DATA",
		TabGroupSub:   "group datagram",
		TabLabel:      "By secret",
		Params: []Param{
			{Name: "secret", Kind: ParamHex, Label: "Channel secret (16 bytes)", Placeholder: "32 hex chars", Secret: true},
			{Name: "dataType", Kind: ParamInt, Label: "Data type", Placeholder: "0"},
			{Name: "data", Kind: ParamHex, Label: "Data (hex)", Optional: true, Widget: "textarea"},
		},
		Result:         []ResultField{{Name: "hex", Kind: ResultString, Label: "Hex packet"}},
		ResultTypeName: "HexResult",
		Run: func(args []any) (map[string]any, error) {
			secret := args[0].([]byte)
			if len(secret) < ChannelSecretLen {
				return nil, fmt.Errorf("secret must be at least %d bytes", ChannelSecretLen)
			}
			pkt, err := GrpDataPacket(secret[:ChannelSecretLen], uint16(args[1].(int)), args[2].([]byte))
			if err != nil {
				return nil, err
			}
			return map[string]any{"hex": hex.EncodeToString(pkt)}, nil
		},
	},

	{
		Name:          "encodeDirectText",
		Category:      "encode",
		Label:         "Encode direct message",
		TabGroup:      "txtmsg",
		TabGroupLabel: "TXT_MSG",
		TabGroupSub:   "direct message",
		TabGroupDoc:   "A private text message addressed to a single peer. Encrypted end-to-end with a shared secret derived from your private key and the peer's public key via X25519 ECDH.",
		Params: []Param{
			{Name: "privKey", Kind: ParamString, Label: "My private key", Placeholder: "64 hex chars", Action: "keypair", Secret: true},
			{Name: "peerPubKey", Kind: ParamString, Label: "Peer public key", Placeholder: "64 hex chars"},
			{Name: "text", Kind: ParamString, Label: "Message", Placeholder: "Hello!", Widget: "textarea"},
		},
		Result: []ResultField{{Name: "hex", Kind: ResultString, Label: "Hex packet"}},
		Run: func(args []any) (map[string]any, error) {
			pkt, err := DirectTextPacketFromKeys(args[0].(string), args[1].(string), args[2].(string), time.Now())
			if err != nil {
				return nil, err
			}
			return map[string]any{"hex": hex.EncodeToString(pkt)}, nil
		},
	},

	{
		Name:          "encodeAdvert",
		Category:      "encode",
		Label:         "Encode ADVERT",
		TabGroup:      "advert",
		TabGroupLabel: "ADVERT",
		TabGroupSub:   "node advertisement",
		TabGroupDoc:   "A self-announcement broadcast so other nodes can discover this one. Carries the node's public key, name, type, and optional GPS position. The contents are public and not encrypted.",
		Params: []Param{
			{Name: "pubKey", Kind: ParamHex, Label: "Public key (32 bytes)", Placeholder: "64 hex chars", Action: "keypair-pub"},
			{Name: "signature", Kind: ParamHex, Label: "Signature (optional, 64 bytes)", Placeholder: "leave empty for zeros", Optional: true},
			{Name: "name", Kind: ParamString, Label: "Node name", Placeholder: "Alice's node"},
			{Name: "hasGPS", Kind: ParamInt, Label: "Include GPS coordinates", Widget: "checkbox"},
			{Name: "lat", Kind: ParamFloat, Label: "Latitude (°)", Placeholder: "51.5074", ShowWhen: "hasGPS", ShowValue: 1, Group: "gps"},
			{Name: "lon", Kind: ParamFloat, Label: "Longitude (°)", Placeholder: "-0.1278", ShowWhen: "hasGPS", ShowValue: 1, Group: "gps"},
		},
		Result:         []ResultField{{Name: "hex", Kind: ResultString, Label: "Hex packet"}},
		ResultTypeName: "HexResult",
		Run: func(args []any) (map[string]any, error) {
			adv := Advert{
				PublicKey: args[0].([]byte),
				Signature: args[1].([]byte),
				Name:      args[2].(string),
				NodeType:  AdvertNodeChat, // default: chat node
				HasGPS:    args[3].(int) != 0,
				Lat:       args[4].(float64),
				Lon:       args[5].(float64),
			}
			payload, err := EncodeAdvertPayload(adv)
			if err != nil {
				return nil, err
			}
			pkt := Packet{
				Route:        RouteFlood,
				Type:         PayloadAdvert,
				Version:      0,
				PathHashSize: 2,
				Payload:      payload,
			}
			raw, err := EncodePacket(pkt)
			if err != nil {
				return nil, err
			}
			return map[string]any{"hex": hex.EncodeToString(raw)}, nil
		},
	},

	{
		Name:          "encodeAck",
		Category:      "encode",
		Label:         "Encode ACK",
		TabGroup:      "ack",
		TabGroupLabel: "ACK",
		TabGroupSub:   "acknowledgement",
		TabGroupDoc:   "A minimal packet confirming receipt of an earlier message. Carries only a CRC32 that identifies the packet being acknowledged.",
		Params: []Param{
			{Name: "crc", Kind: ParamInt, Label: "CRC32 value", Placeholder: "0"},
		},
		Result:         []ResultField{{Name: "hex", Kind: ResultString, Label: "Hex packet"}},
		ResultTypeName: "HexResult",
		Run: func(args []any) (map[string]any, error) {
			pkt, err := AckPacket(uint32(args[0].(int)))
			if err != nil {
				return nil, err
			}
			return map[string]any{"hex": hex.EncodeToString(pkt)}, nil
		},
	},

	{
		Name:          "encodeTextAck",
		Category:      "encode",
		Label:         "Encode TXT_MSG ACK",
		TabGroup:      "ack",
		TabGroupLabel: "ACK",
		TabGroupSub:   "acknowledge a direct message",
		TabGroupDoc:   "Builds the ACK packet a recipient returns for a received direct text message (TXT_MSG). The CRC is derived from the message's timestamp, attempt, text, and the sender's public key — exactly as MeshCore firmware computes the expected ACK.",
		Params: []Param{
			{Name: "timestamp", Kind: ParamInt, Label: "Message timestamp (epoch seconds)", Placeholder: "0"},
			{Name: "attempt", Kind: ParamInt, Label: "Attempt (0–3)", Placeholder: "0"},
			{Name: "text", Kind: ParamString, Label: "Message text", Placeholder: "Hello!", Widget: "textarea"},
			{Name: "senderPubKey", Kind: ParamHex, Label: "Sender public key (32 bytes)", Placeholder: "64 hex chars"},
		},
		Result:         []ResultField{{Name: "hex", Kind: ResultString, Label: "Hex packet"}},
		ResultTypeName: "HexResult",
		Run: func(args []any) (map[string]any, error) {
			pkt, err := TextAckPacket(uint32(args[0].(int)), byte(args[1].(int)), args[2].(string), args[3].([]byte))
			if err != nil {
				return nil, err
			}
			return map[string]any{"hex": hex.EncodeToString(pkt)}, nil
		},
	},

	{
		Name:          "encodeReq",
		Category:      "encode",
		Label:         "Encode request",
		TabGroup:      "req",
		TabGroupLabel: "REQ",
		TabGroupSub:   "request",
		TabGroupDoc:   "An encrypted request sent to a known peer (e.g. login, get stats, keepalive). Uses X25519 ECDH shared-secret encryption with a request-type byte selecting the operation.",
		Params: []Param{
			{Name: "privKey", Kind: ParamString, Label: "My private key", Placeholder: "64 hex chars", Action: "keypair", Secret: true},
			{Name: "peerPubKey", Kind: ParamString, Label: "Peer public key", Placeholder: "64 hex chars"},
			{Name: "reqType", Kind: ParamInt, Label: "Request type", Choices: []Choice{{0, "Custom"}, {1, "Get stats"}, {2, "Keepalive"}, {3, "Clock+status"}}},
			{Name: "data", Kind: ParamHex, Label: "Extra data (hex)", Optional: true, Widget: "textarea"},
		},
		Result:         []ResultField{{Name: "hex", Kind: ResultString, Label: "Hex packet"}},
		ResultTypeName: "HexResult",
		Run: func(args []any) (map[string]any, error) {
			pkt, err := ReqPacketFromKeys(args[0].(string), args[1].(string), byte(args[2].(int)), args[3].([]byte))
			if err != nil {
				return nil, err
			}
			return map[string]any{"hex": hex.EncodeToString(pkt)}, nil
		},
	},

	{
		Name:          "encodeAnonReq",
		Category:      "encode",
		Label:         "Encode anonymous request",
		TabGroup:      "anonreq",
		TabGroupLabel: "ANON_REQ",
		TabGroupSub:   "anonymous request",
		TabGroupDoc:   "A first-contact request from a sender the recipient doesn't yet know. The sender's ephemeral public key is embedded so the recipient can derive the shared ECDH secret — used when initially connecting to a repeater or room server.",
		Params: []Param{
			{Name: "destPubKey", Kind: ParamHex, Label: "Destination public key (32 bytes)", Placeholder: "64 hex chars"},
			{Name: "myPrivKey", Kind: ParamString, Label: "My private key", Placeholder: "64 hex chars", Action: "keypair", Secret: true},
			{Name: "data", Kind: ParamHex, Label: "Request body (hex)", Optional: true, Widget: "textarea"},
		},
		Result:         []ResultField{{Name: "hex", Kind: ResultString, Label: "Hex packet"}},
		ResultTypeName: "HexResult",
		Run: func(args []any) (map[string]any, error) {
			pkt, err := AnonReqPacket(args[0].([]byte), args[1].(string), args[2].([]byte))
			if err != nil {
				return nil, err
			}
			return map[string]any{"hex": hex.EncodeToString(pkt)}, nil
		},
	},

	{
		Name:          "encodeDiscoverReq",
		Category:      "encode",
		Label:         "Encode CONTROL/DISCOVER_REQ",
		TabGroup:      "control",
		TabGroupLabel: "CONTROL",
		TabGroupSub:   "control data",
		TabGroupDoc:   "Protocol control packets such as discovery requests and responses. They carry a sub-type and flags rather than user content, and are used for node discovery and network management.",
		Params: []Param{
			{Name: "typeFilter", Kind: ParamInt, Label: "Node type filter", Choices: []Choice{{0, "All nodes"}, {1, "Chat"}, {2, "Repeater"}, {4, "Room"}, {8, "Sensor"}}},
			{Name: "tag", Kind: ParamInt, Label: "Random tag", Placeholder: "0"},
			{Name: "since", Kind: ParamInt, Label: "Since (epoch, 0=all)", Placeholder: "0", Optional: true},
			{Name: "prefixOnly", Kind: ParamInt, Label: "Prefix-key response only", Widget: "checkbox"},
		},
		Result:         []ResultField{{Name: "hex", Kind: ResultString, Label: "Hex packet"}},
		ResultTypeName: "HexResult",
		Run: func(args []any) (map[string]any, error) {
			pkt, err := DiscoverReqPacket(byte(args[0].(int)), uint32(args[1].(int)), uint32(args[2].(int)), args[3].(int) != 0)
			if err != nil {
				return nil, err
			}
			return map[string]any{"hex": hex.EncodeToString(pkt)}, nil
		},
	},

	{
		Name:          "encodeTrace",
		Category:      "encode",
		Label:         "Encode TRACE",
		TabGroup:      "trace",
		TabGroupLabel: "TRACE",
		TabGroupSub:   "path trace",
		Params: []Param{
			{Name: "tag", Kind: ParamInt, Label: "Tag (random)", Placeholder: "0"},
			{Name: "authCode", Kind: ParamInt, Label: "Auth code (opaque)", Placeholder: "0"},
			{Name: "flags", Kind: ParamInt, Label: "Flags (hash width: 0=1B 1=2B 2=4B 3=8B)", Placeholder: "0"},
			{Name: "routeHashes", Kind: ParamHex, Label: "Route hashes (hex)", Optional: true, Widget: "textarea"},
		},
		Result:         []ResultField{{Name: "hex", Kind: ResultString, Label: "Hex packet"}},
		ResultTypeName: "HexResult",
		Run: func(args []any) (map[string]any, error) {
			pkt, err := TracePacket(uint32(args[0].(int)), uint32(args[1].(int)), byte(args[2].(int)), args[3].([]byte))
			if err != nil {
				return nil, err
			}
			return map[string]any{"hex": hex.EncodeToString(pkt)}, nil
		},
	},

	{
		Name:          "encodeMultipartAck",
		Category:      "encode",
		Label:         "Encode MULTIPART ACK",
		TabGroup:      "multipart",
		TabGroupLabel: "MULTIPART",
		TabGroupSub:   "repeated ACK",
		Params: []Param{
			{Name: "remaining", Kind: ParamInt, Label: "Remaining (packets still to send after this)", Placeholder: "0"},
			{Name: "crc", Kind: ParamInt, Label: "ACK CRC32", Placeholder: "0"},
		},
		Result:         []ResultField{{Name: "hex", Kind: ResultString, Label: "Hex packet"}},
		ResultTypeName: "HexResult",
		Run: func(args []any) (map[string]any, error) {
			pkt, err := MultipartAckPacket(byte(args[0].(int)), uint32(args[1].(int)))
			if err != nil {
				return nil, err
			}
			return map[string]any{"hex": hex.EncodeToString(pkt)}, nil
		},
	},

	{
		Name:          "encodeRaw",
		Category:      "encode",
		Label:         "Encode raw packet",
		TabGroup:      "raw",
		TabGroupLabel: "RAW",
		TabGroupSub:   "any type",
		TabGroupDoc:   "Build a packet from raw header fields (route, payload type, version, path-hash size) and an arbitrary payload hex blob — bypassing the typed encoders. Useful for manual construction and experimentation.",
		Params: []Param{
			{Name: "route", Kind: ParamInt, Label: "Route type", Choices: allRouteChoices, Group: "hdr"},
			{Name: "payloadType", Kind: ParamInt, Label: "Payload type", Choices: allPayloadTypeChoices, Group: "hdr"},
			{Name: "version", Kind: ParamInt, Label: "Version (0–3)", Placeholder: "0", Group: "ver"},
			{Name: "pathHashSize", Kind: ParamInt, Label: "Path hash size", Choices: hashSizeChoices, Group: "ver"},
			{Name: "payload", Kind: ParamHex, Label: "Payload (hex)", Placeholder: "empty = bare packet", Optional: true, Widget: "textarea"},
		},
		Result: []ResultField{{Name: "hex", Kind: ResultString, Label: "Hex packet"}},
		Run: func(args []any) (map[string]any, error) {
			pkt := Packet{
				Route:        RouteType(args[0].(int)),
				Type:         PayloadType(args[1].(int)),
				Version:      byte(args[2].(int)),
				PathHashSize: args[3].(int),
				Payload:      args[4].([]byte),
			}
			raw, err := EncodePacket(pkt)
			if err != nil {
				return nil, err
			}
			return map[string]any{"hex": hex.EncodeToString(raw)}, nil
		},
	},

	// ── decoders ──────────────────────────────────────────────────────────────

	{
		Name:     "decodeEnvelope",
		Category: "decode",
		Label:    "Decode packet envelope",
		// No TabGroup/PacketType — this is always step 1, never a generic step-2 form.
		Params: []Param{
			{Name: "packet", Kind: ParamHex, Label: "Hex packet"},
		},
		Result: []ResultField{
			{Name: "route", Kind: ResultString, Label: "Route"},
			{Name: "routeCode", Kind: ResultNumber, Label: "Route code"},
			{Name: "type", Kind: ResultString, Label: "Payload type"},
			{Name: "typeCode", Kind: ResultNumber, Label: "Type code"},
			{Name: "version", Kind: ResultNumber, Label: "Version"},
			{Name: "pathHashSize", Kind: ResultNumber, Label: "Path hash size"},
			{Name: "hopCount", Kind: ResultNumber, Label: "Hop count"},
			{Name: "hops", Kind: ResultStringArray, Label: "Hops"},
			{Name: "payloadHex", Kind: ResultString, Label: "Payload (hex)"},
			{Name: "isTransport", Kind: ResultBool, Label: "Is transport"},
			{Name: "transportCodes", Kind: ResultNumberPair, Optional: true, Label: "Transport codes"},
		},
		ResultTypeName: "Envelope",
		Run: func(args []any) (map[string]any, error) {
			pkt, err := DecodePacket(args[0].([]byte))
			if err != nil {
				return nil, err
			}
			hops := pkt.Hops()
			hopHex := make([]any, len(hops))
			for i, h := range hops {
				hopHex[i] = hex.EncodeToString(h)
			}
			result := map[string]any{
				"route":        pkt.Route.String(),
				"routeCode":    int(pkt.Route),
				"type":         pkt.Type.String(),
				"typeCode":     int(pkt.Type),
				"version":      int(pkt.Version),
				"pathHashSize": pkt.PathHashSize,
				"hopCount":     pkt.HopCount(),
				"hops":         hopHex,
				"payloadHex":   hex.EncodeToString(pkt.Payload),
				"isTransport":  pkt.Route.IsTransport(),
			}
			if pkt.Route.IsTransport() {
				result["transportCodes"] = []any{int(pkt.TransportCodes[0]), int(pkt.TransportCodes[1])}
			}
			return result, nil
		},
	},

	{
		Name:       "decodeGroupText",
		Category:   "decode",
		Label:      "Decrypt GRP_TXT by channel name",
		TabGroup:   "grptxt",
		PacketType: "GRP_TXT",
		TabLabel:   "By name",
		Params: []Param{
			{Name: "payload", Kind: ParamHex, AutoFill: "payloadHex"},
			{Name: "channelName", Kind: ParamString, Label: "Channel name", Placeholder: "#test"},
		},
		Result: []ResultField{
			{Name: "sender", Kind: ResultString, Label: "Sender"},
			{Name: "text", Kind: ResultString, Label: "Message"},
			{Name: "timestamp", Kind: ResultNumber, Label: "Timestamp"},
			{Name: "txtType", Kind: ResultNumber, Label: "Type code"},
			{Name: "attempt", Kind: ResultNumber, Label: "Attempt"},
			{Name: "channelHash", Kind: ResultString, Label: "Channel hash"},
		},
		ResultTypeName: "GroupTextPayload",
		Run: func(args []any) (map[string]any, error) {
			secret := DeriveChannelSecret(args[1].(string))
			gt, err := DecodeGroupTextPayload(secret, args[0].([]byte))
			if err != nil {
				return nil, err
			}
			return opGroupTextResult(gt, secret), nil
		},
	},

	{
		Name:       "decodeGroupTextSecret",
		Category:   "decode",
		Label:      "Decrypt GRP_TXT by channel secret",
		TabGroup:   "grptxt",
		PacketType: "GRP_TXT",
		TabLabel:   "By secret",
		Params: []Param{
			{Name: "payload", Kind: ParamHex, AutoFill: "payloadHex"},
			{Name: "secret", Kind: ParamHex, Label: "Channel secret (16 bytes)", Placeholder: "32 hex chars", Secret: true},
		},
		Result: []ResultField{
			{Name: "sender", Kind: ResultString, Label: "Sender"},
			{Name: "text", Kind: ResultString, Label: "Message"},
			{Name: "timestamp", Kind: ResultNumber, Label: "Timestamp"},
			{Name: "txtType", Kind: ResultNumber, Label: "Type code"},
			{Name: "attempt", Kind: ResultNumber, Label: "Attempt"},
			{Name: "channelHash", Kind: ResultString, Label: "Channel hash"},
		},
		Run: func(args []any) (map[string]any, error) {
			secret := args[1].([]byte)
			if len(secret) < ChannelSecretLen {
				return nil, fmt.Errorf("secret must be at least %d bytes", ChannelSecretLen)
			}
			secret = secret[:ChannelSecretLen]
			gt, err := DecodeGroupTextPayload(secret, args[0].([]byte))
			if err != nil {
				return nil, err
			}
			return opGroupTextResult(gt, secret), nil
		},
	},

	{
		Name:       "decodeDirectText",
		Category:   "decode",
		Label:      "Decrypt TXT_MSG",
		PacketType: "TXT_MSG",
		Params: []Param{
			{Name: "payload", Kind: ParamHex, AutoFill: "payloadHex"},
			{Name: "privKey", Kind: ParamString, Label: "My private key", Placeholder: "64 hex chars", Action: "keypair", Secret: true},
			{Name: "peerPubKey", Kind: ParamString, Label: "Peer public key", Placeholder: "64 hex chars"},
		},
		Result: []ResultField{
			{Name: "destHash", Kind: ResultString, Label: "Dest node hash"},
			{Name: "srcHash", Kind: ResultString, Label: "Src node hash"},
			{Name: "text", Kind: ResultString, Label: "Message"},
			{Name: "timestamp", Kind: ResultNumber, Label: "Timestamp"},
			{Name: "txtType", Kind: ResultNumber, Label: "Type code"},
			{Name: "attempt", Kind: ResultNumber, Label: "Attempt"},
		},
		ResultTypeName: "DirectTextPayload",
		Run: func(args []any) (map[string]any, error) {
			dt, err := DecodeDirectTextPayloadFromKeys(args[0].([]byte), args[1].(string), args[2].(string))
			if err != nil {
				return nil, err
			}
			return map[string]any{
				"destHash":  fmt.Sprintf("%02x", dt.DestHash),
				"srcHash":   fmt.Sprintf("%02x", dt.SrcHash),
				"text":      dt.Text,
				"timestamp": dt.Timestamp.Unix(),
				"txtType":   int(dt.TxtType),
				"attempt":   int(dt.Attempt),
			}, nil
		},
	},

	{
		Name:       "decodeAdvert",
		Category:   "decode",
		Label:      "Decode ADVERT",
		PacketType: "ADVERT",
		// Auto-decode: payload only, no user input needed.
		Params: []Param{
			{Name: "payload", Kind: ParamHex, AutoFill: "payloadHex"},
		},
		Result: []ResultField{
			{Name: "publicKey", Kind: ResultString, Label: "Public key"},
			{Name: "timestamp", Kind: ResultNumber, Label: "Timestamp"},
			{Name: "name", Kind: ResultString, Label: "Node name"},
			{Name: "nodeType", Kind: ResultNumber, Label: "Node type"},
			{Name: "hasGPS", Kind: ResultBool, Label: "Has GPS"},
			{Name: "lat", Kind: ResultNumber, Optional: true, Label: "Latitude"},
			{Name: "lon", Kind: ResultNumber, Optional: true, Label: "Longitude"},
			{Name: "sigVerified", Kind: ResultBool, Label: "Signature verified"},
		},
		ResultTypeName: "AdvertPayload",
		Run: func(args []any) (map[string]any, error) {
			payload := args[0].([]byte)
			adv, err := DecodeAdvertPayload(payload)
			if err != nil {
				return nil, err
			}
			result := map[string]any{
				"publicKey":   hex.EncodeToString(adv.PublicKey),
				"timestamp":   adv.Timestamp.Unix(),
				"name":        adv.Name,
				"nodeType":    int(adv.NodeType),
				"hasGPS":      adv.HasGPS,
				"sigVerified": !allZero(adv.Signature), // true = non-zero sig that passed verification
			}
			if adv.HasGPS {
				result["lat"] = adv.Lat
				result["lon"] = adv.Lon
			}
			return result, nil
		},
	},

	{
		Name:       "decodeAck",
		Category:   "decode",
		Label:      "Decode ACK",
		PacketType: "ACK",
		Params: []Param{
			{Name: "payload", Kind: ParamHex, AutoFill: "payloadHex"},
		},
		Result: []ResultField{
			{Name: "crc", Kind: ResultNumber, Label: "CRC32"},
			{Name: "crcHex", Kind: ResultString, Label: "CRC32 (hex)"},
		},
		ResultTypeName: "AckPayload",
		Run: func(args []any) (map[string]any, error) {
			crc, err := DecodeAckPayload(args[0].([]byte))
			if err != nil {
				return nil, err
			}
			return map[string]any{
				"crc":    int(crc),
				"crcHex": fmt.Sprintf("%08x", crc),
			}, nil
		},
	},

	{
		Name:       "decodeGrpData",
		Category:   "decode",
		Label:      "Decode GRP_DATA by channel name",
		PacketType: "GRP_DATA",
		TabGroup:   "grpdata",
		TabLabel:   "By name",
		Params: []Param{
			{Name: "payload", Kind: ParamHex, AutoFill: "payloadHex"},
			{Name: "channelName", Kind: ParamString, Label: "Channel name", Placeholder: "#test"},
		},
		Result: []ResultField{
			{Name: "channelHash", Kind: ResultString, Label: "Channel hash"},
			{Name: "dataType", Kind: ResultNumber, Label: "Data type"},
			{Name: "dataHex", Kind: ResultString, Label: "Data"},
		},
		ResultTypeName: "GrpDataPayload",
		Run: func(args []any) (map[string]any, error) {
			gd, err := DecodeGrpDataPayloadByName(args[1].(string), args[0].([]byte))
			if err != nil {
				return nil, err
			}
			return opGrpDataResult(gd), nil
		},
	},

	{
		Name:       "decodeGrpDataSecret",
		Category:   "decode",
		Label:      "Decode GRP_DATA by channel secret",
		PacketType: "GRP_DATA",
		TabGroup:   "grpdata",
		TabLabel:   "By secret",
		Params: []Param{
			{Name: "payload", Kind: ParamHex, AutoFill: "payloadHex"},
			{Name: "secret", Kind: ParamHex, Label: "Channel secret (16 bytes)", Placeholder: "32 hex chars", Secret: true},
		},
		Result: []ResultField{
			{Name: "channelHash", Kind: ResultString, Label: "Channel hash"},
			{Name: "dataType", Kind: ResultNumber, Label: "Data type"},
			{Name: "dataHex", Kind: ResultString, Label: "Data"},
		},
		Run: func(args []any) (map[string]any, error) {
			secret := args[1].([]byte)
			if len(secret) < ChannelSecretLen {
				return nil, fmt.Errorf("secret must be at least %d bytes", ChannelSecretLen)
			}
			gd, err := DecodeGrpDataPayload(secret[:ChannelSecretLen], args[0].([]byte))
			if err != nil {
				return nil, err
			}
			return opGrpDataResult(gd), nil
		},
	},

	{
		Name:       "decodeReq",
		Category:   "decode",
		Label:      "Decrypt REQ",
		PacketType: "REQ",
		Params: []Param{
			{Name: "payload", Kind: ParamHex, AutoFill: "payloadHex"},
			{Name: "privKey", Kind: ParamString, Label: "My private key", Placeholder: "64 hex chars", Action: "keypair", Secret: true},
			{Name: "peerPubKey", Kind: ParamString, Label: "Peer public key", Placeholder: "64 hex chars"},
		},
		Result: []ResultField{
			{Name: "destHash", Kind: ResultString, Label: "Dest node hash"},
			{Name: "srcHash", Kind: ResultString, Label: "Src node hash"},
			{Name: "timestamp", Kind: ResultNumber, Label: "Timestamp"},
			{Name: "reqType", Kind: ResultNumber, Label: "Request type"},
			{Name: "dataHex", Kind: ResultString, Label: "Data"},
		},
		ResultTypeName: "ReqPayload",
		Run: func(args []any) (map[string]any, error) {
			r, err := DecodeReqPayloadFromKeys(args[0].([]byte), args[1].(string), args[2].(string))
			if err != nil {
				return nil, err
			}
			return map[string]any{
				"destHash":  fmt.Sprintf("%02x", r.DestHash),
				"srcHash":   fmt.Sprintf("%02x", r.SrcHash),
				"timestamp": r.Timestamp.Unix(),
				"reqType":   int(r.ReqType),
				"dataHex":   hex.EncodeToString(r.Data),
			}, nil
		},
	},

	{
		Name:        "decodeResponse",
		Category:    "decode",
		Label:       "Decrypt RESPONSE",
		PacketType:  "RESPONSE",
		TabGroupDoc: "The encrypted reply to a REQ packet, addressed back to the requester and secured with the same X25519 ECDH shared secret.",
		Params: []Param{
			{Name: "payload", Kind: ParamHex, AutoFill: "payloadHex"},
			{Name: "privKey", Kind: ParamString, Label: "My private key", Placeholder: "64 hex chars", Action: "keypair", Secret: true},
			{Name: "peerPubKey", Kind: ParamString, Label: "Peer public key", Placeholder: "64 hex chars"},
		},
		Result: []ResultField{
			{Name: "destHash", Kind: ResultString, Label: "Dest node hash"},
			{Name: "srcHash", Kind: ResultString, Label: "Src node hash"},
			{Name: "dataHex", Kind: ResultString, Label: "Data"},
		},
		ResultTypeName: "ResponsePayload",
		Run: func(args []any) (map[string]any, error) {
			r, err := DecodeResponsePayloadFromKeys(args[0].([]byte), args[1].(string), args[2].(string))
			if err != nil {
				return nil, err
			}
			return map[string]any{
				"destHash": fmt.Sprintf("%02x", r.DestHash),
				"srcHash":  fmt.Sprintf("%02x", r.SrcHash),
				"dataHex":  hex.EncodeToString(r.Data),
			}, nil
		},
	},

	{
		Name:        "decodePath",
		Category:    "decode",
		Label:       "Decrypt PATH",
		PacketType:  "PATH",
		TabGroupDoc: "Carries a discovered route — the ordered list of hop hashes — back toward a peer, optionally with an extra piggy-backed payload. Used to establish return paths through the mesh.",
		Params: []Param{
			{Name: "payload", Kind: ParamHex, AutoFill: "payloadHex"},
			{Name: "privKey", Kind: ParamString, Label: "My private key", Placeholder: "64 hex chars", Action: "keypair", Secret: true},
			{Name: "peerPubKey", Kind: ParamString, Label: "Peer public key", Placeholder: "64 hex chars"},
		},
		Result: []ResultField{
			{Name: "destHash", Kind: ResultString, Label: "Dest node hash"},
			{Name: "srcHash", Kind: ResultString, Label: "Src node hash"},
			{Name: "path", Kind: ResultStringArray, Label: "Path hops"},
			{Name: "extraType", Kind: ResultNumber, Label: "Extra type"},
			{Name: "extraHex", Kind: ResultString, Label: "Extra data"},
		},
		ResultTypeName: "PathPayload",
		Run: func(args []any) (map[string]any, error) {
			p, err := DecodePathPayloadFromKeys(args[0].([]byte), args[1].(string), args[2].(string))
			if err != nil {
				return nil, err
			}
			hashes := p.PathHashes()
			hs := make([]any, len(hashes))
			for i, h := range hashes {
				hs[i] = h
			}
			return map[string]any{
				"destHash":  fmt.Sprintf("%02x", p.DestHash),
				"srcHash":   fmt.Sprintf("%02x", p.SrcHash),
				"path":      hs,
				"extraType": int(p.ExtraType),
				"extraHex":  hex.EncodeToString(p.Extra),
			}, nil
		},
	},

	{
		Name:       "decodeAnonReq",
		Category:   "decode",
		Label:      "Decrypt ANON_REQ",
		PacketType: "ANON_REQ",
		Params: []Param{
			{Name: "payload", Kind: ParamHex, AutoFill: "payloadHex"},
			{Name: "myPrivKey", Kind: ParamString, Label: "My private key (recipient)", Placeholder: "64 hex chars", Action: "keypair", Secret: true},
		},
		Result: []ResultField{
			{Name: "destHash", Kind: ResultString, Label: "Dest node hash"},
			{Name: "senderPubKey", Kind: ResultString, Label: "Sender public key"},
			{Name: "timestamp", Kind: ResultNumber, Label: "Timestamp"},
			{Name: "dataHex", Kind: ResultString, Label: "Data"},
		},
		ResultTypeName: "AnonReqPayload",
		Run: func(args []any) (map[string]any, error) {
			a, err := DecodeAnonReqPayload(args[0].([]byte), args[1].(string))
			if err != nil {
				return nil, err
			}
			return map[string]any{
				"destHash":     fmt.Sprintf("%02x", a.DestHash),
				"senderPubKey": hex.EncodeToString(a.SenderPubKey),
				"timestamp":    a.Timestamp.Unix(),
				"dataHex":      hex.EncodeToString(a.Data),
			}, nil
		},
	},

	{
		Name:       "decodeControl",
		Category:   "decode",
		Label:      "Decode CONTROL",
		PacketType: "CONTROL",
		// Auto-decode: payload only, no user input needed.
		Params: []Param{
			{Name: "payload", Kind: ParamHex, AutoFill: "payloadHex"},
		},
		Result: []ResultField{
			{Name: "subType", Kind: ResultNumber, Label: "Sub-type"},
			{Name: "flags", Kind: ResultNumber, Label: "Flags"},
			{Name: "dataHex", Kind: ResultString, Label: "Data"},
			{Name: "discoverTag", Kind: ResultNumber, Optional: true, Label: "Tag"},
			{Name: "discoverTypeFilter", Kind: ResultNumber, Optional: true, Label: "Type filter"},
			{Name: "discoverSince", Kind: ResultNumber, Optional: true, Label: "Since"},
			{Name: "discoverNodeType", Kind: ResultNumber, Optional: true, Label: "Node type"},
			{Name: "discoverSNR", Kind: ResultNumber, Optional: true, Label: "SNR (dB)"},
			{Name: "discoverPubKey", Kind: ResultString, Optional: true, Label: "Public key"},
		},
		ResultTypeName: "ControlPayload",
		Run: func(args []any) (map[string]any, error) {
			c, err := DecodeControlPayload(args[0].([]byte))
			if err != nil {
				return nil, err
			}
			result := map[string]any{
				"subType": int(c.SubType),
				"flags":   int(c.Flags),
				"dataHex": hex.EncodeToString(c.Data),
			}
			if c.DiscoverReq != nil {
				result["discoverTag"] = int(c.DiscoverReq.Tag)
				result["discoverTypeFilter"] = int(c.DiscoverReq.TypeFilter)
				result["discoverSince"] = int(c.DiscoverReq.Since)
			}
			if c.DiscoverResp != nil {
				result["discoverNodeType"] = int(c.DiscoverResp.NodeType)
				result["discoverSNR"] = c.DiscoverResp.SNR
				result["discoverPubKey"] = c.DiscoverResp.PubKey
			}
			return result, nil
		},
	},

	{
		// TRACE is special: SNR bytes live in Packet.Path, not the payload.
		// This op therefore takes the full packet hex, not just payloadHex.
		Name:       "decodeTrace",
		Category:   "decode",
		Label:      "Decode TRACE packet",
		PacketType: "TRACE",
		Params: []Param{
			{Name: "packet", Kind: ParamHex, AutoFill: "packetHex", Label: "Full packet hex (SNR bytes are in the path field)"},
		},
		Result: []ResultField{
			{Name: "tag", Kind: ResultNumber, Label: "Tag"},
			{Name: "authCode", Kind: ResultNumber, Label: "Auth code"},
			{Name: "flags", Kind: ResultNumber, Label: "Flags"},
			{Name: "hashWidth", Kind: ResultNumber, Label: "Route hash width (bytes)"},
			{Name: "routeHashes", Kind: ResultStringArray, Label: "Route hashes"},
			{Name: "snrs", Kind: ResultStringArray, Label: "SNR values (dB)"},
			{Name: "hopCount", Kind: ResultNumber, Label: "Hops with SNR"},
		},
		ResultTypeName: "TracePayload",
		Run: func(args []any) (map[string]any, error) {
			pkt, err := DecodePacket(args[0].([]byte))
			if err != nil {
				return nil, err
			}
			if pkt.Type != PayloadTrace {
				return nil, fmt.Errorf("expected TRACE packet, got %s", pkt.Type)
			}
			t, err := DecodeTracePayload(pkt.Payload)
			if err != nil {
				return nil, err
			}
			snrs := TraceSNRs(pkt.Path)
			return map[string]any{
				"tag":         int(t.Tag),
				"authCode":    int(t.AuthCode),
				"flags":       int(t.Flags),
				"hashWidth":   t.HashWidth(),
				"routeHashes": traceRouteHashHex(t),
				"snrs":        traceSNRStrings(snrs),
				"hopCount":    len(snrs),
			}, nil
		},
	},

	{
		Name:       "decodeMultipart",
		Category:   "decode",
		Label:      "Decode MULTIPART",
		PacketType: "MULTIPART",
		Params: []Param{
			{Name: "payload", Kind: ParamHex, AutoFill: "payloadHex"},
		},
		Result: []ResultField{
			{Name: "remaining", Kind: ResultNumber, Label: "Remaining packets"},
			{Name: "innerType", Kind: ResultString, Label: "Inner type"},
			{Name: "innerTypeCode", Kind: ResultNumber, Label: "Inner type code"},
			{Name: "innerPayloadHex", Kind: ResultString, Label: "Inner payload (hex)"},
			{Name: "ackCrc", Kind: ResultNumber, Optional: true, Label: "ACK CRC32"},
			{Name: "ackCrcHex", Kind: ResultString, Optional: true, Label: "ACK CRC32 (hex)"},
		},
		ResultTypeName: "MultipartPayload",
		Run: func(args []any) (map[string]any, error) {
			m, err := DecodeMultipartPayload(args[0].([]byte))
			if err != nil {
				return nil, err
			}
			result := map[string]any{
				"remaining":       int(m.Remaining),
				"innerType":       m.InnerType.String(),
				"innerTypeCode":   int(m.InnerType),
				"innerPayloadHex": hex.EncodeToString(m.InnerPayload),
			}
			if m.InnerType == PayloadAck {
				if crc, err := DecodeAckPayload(m.InnerPayload); err == nil {
					result["ackCrc"] = int(crc)
					result["ackCrcHex"] = fmt.Sprintf("%08x", crc)
				}
			}
			return result, nil
		},
	},

	// ── utilities ─────────────────────────────────────────────────────────────

	{
		Name:     "generateKeypair",
		Category: "key",
		Label:    "Generate keypair",
		Params:   []Param{},
		Result: []ResultField{
			{Name: "publicKey", Kind: ResultString, Label: "Public key"},
			{Name: "privateKey", Kind: ResultString, Label: "Private key"},
		},
		ResultTypeName: "KeypairResult",
		Run: func(args []any) (map[string]any, error) {
			kp, err := Generate()
			if err != nil {
				return nil, err
			}
			return map[string]any{"publicKey": kp.PublicKey, "privateKey": kp.PrivateKey}, nil
		},
	},

	{
		Name:     "deriveChannelSecret",
		Category: "key",
		Label:    "Derive channel secret",
		Params: []Param{
			{Name: "channelName", Kind: ParamString, Label: "Channel name", Placeholder: "#test"},
		},
		Result: []ResultField{{Name: "hex", Kind: ResultString, Label: "Secret (hex)"}},
		Run: func(args []any) (map[string]any, error) {
			return map[string]any{"hex": hex.EncodeToString(DeriveChannelSecret(args[0].(string)))}, nil
		},
	},

	{
		Name:     "sharedSecret",
		Category: "key",
		Label:    "Compute shared secret",
		Params: []Param{
			{Name: "privKey", Kind: ParamString, Label: "My private key", Placeholder: "64 hex chars", Secret: true},
			{Name: "peerPubKey", Kind: ParamString, Label: "Peer public key", Placeholder: "64 hex chars"},
		},
		Result: []ResultField{{Name: "hex", Kind: ResultString, Label: "Shared secret (hex)"}},
		Run: func(args []any) (map[string]any, error) {
			shared, err := SharedSecret(args[0].(string), args[1].(string))
			if err != nil {
				return nil, err
			}
			return map[string]any{"hex": hex.EncodeToString(shared)}, nil
		},
	},
}

// opGrpDataResult builds the result map for a decoded GRP_DATA payload.
func opGrpDataResult(gd GrpData) map[string]any {
	return map[string]any{
		"channelHash": fmt.Sprintf("%02x", gd.ChannelHash),
		"dataType":    int(gd.DataType),
		"dataHex":     hex.EncodeToString(gd.Data),
	}
}

// opGroupTextResult builds the result map for a decoded GRP_TXT message.
func opGroupTextResult(gt GroupText, secret []byte) map[string]any {
	return map[string]any{
		"sender":      gt.Sender,
		"text":        gt.Text,
		"timestamp":   gt.Timestamp.Unix(),
		"txtType":     int(gt.TxtType),
		"attempt":     int(gt.Attempt),
		"channelHash": fmt.Sprintf("%02x", ChannelHash(secret)),
	}
}
