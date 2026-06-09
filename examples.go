package meshpkt

// Examples contains real MeshCore packets captured from hardware.
// They serve as integration test vectors and documentation of the wire format.
// Add new entries as you capture them from the network.
var Examples = []Example{
	{
		Type:        "ADVERT",
		Label:       "CZ.NIC Repeater (Prague)",
		Description: "ADVERT via FLOOD, 5 hops (hashSize=2), GPS included. Captured 2026-06-09.",
		Hex:         "11453287568f06bf2d5ad94765d9aaa4aef45a465a5a84142b5abb55eafe11980bc7b891218a83ebb08f0ba84789276a31c13dad4caf71b6b7f99c1fdfccaa7c1db9d1696be4416a274f3417182d77d486d4faa2a7b3bcc2035c9d8a27af4b2ab45b2b6bc75037c31fd316829639230e929a25fc02a082dc00435a2e4e4943205265706561746572",
		// Decoded:
		//   Route:       FLOOD (0x01)
		//   Type:        ADVERT (0x04)
		//   PathHashSize: 2 B/hop
		//   Hops:        3287 → 568f → 06bf → 2d5a → d947
		//   PublicKey:   65d9aaa4aef45a465a5a84142b5abb55eafe11980bc7b891218a83ebb08f0ba8
		//   Timestamp:   2026-06-09 (unix 1780975943)
		//   NodeType:    Repeater (0x02)
		//   HasGPS:      true  (flag 0x80)
		//   Lat:         +50.01257° N  (int32 LE: 0x02fc259a)
		//   Lon:         +14.45136° E  (int32 LE: 0x00dc82a0)
		//   Name:        "CZ.NIC Repeater"
	},
}

// Example is a single hardware-captured packet.
type Example struct {
	Type        string // PayloadType string, e.g. "ADVERT"
	Label       string // short human label
	Description string // capture context, date, notable fields
	Hex         string // lowercase hex, no spaces
}
