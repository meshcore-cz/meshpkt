package meshpkt

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func TestCallJSON_encodeGroupText(t *testing.T) {
	out := CallJSON("encodeGroupText", `["#test","Alice","hi"]`)
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["error"]; ok {
		t.Fatalf("unexpected error: %v", m["error"])
	}
	hex, ok := m["hex"].(string)
	if !ok || len(hex) < 4 {
		t.Fatalf("want hex result, got %#v", m)
	}
}

func TestCallJSON_decodeAdvertFeatures(t *testing.T) {
	payload, err := EncodeAdvertPayload(Advert{
		PublicKey: make([]byte, 32),
		NodeType:  AdvertNodeRepeater,
		Name:      "Repeater",
		HasFeat1:  true,
		Feature1:  0x4E01,
		HasFeat2:  true,
		Feature2:  0x8003,
	})
	if err != nil {
		t.Fatal(err)
	}

	out := CallJSON("decodeAdvert", `["`+hex.EncodeToString(payload)+`"]`)
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatal(err)
	}
	if e, ok := m["error"]; ok {
		t.Fatalf("unexpected error: %v", e)
	}
	if got := m["feat1"].(float64); got != 0x4E01 {
		t.Errorf("feat1 = %v, want %d", got, 0x4E01)
	}
	if got := m["feat1Hex"].(string); got != "0x4E01" {
		t.Errorf("feat1Hex = %q, want 0x4E01", got)
	}
	if got := m["feat2"].(float64); got != 0x8003 {
		t.Errorf("feat2 = %v, want %d", got, 0x8003)
	}
	if got := m["feat2Hex"].(string); got != "0x8003" {
		t.Errorf("feat2Hex = %q, want 0x8003", got)
	}
}

func TestCallJSON_decodeAdvertNoFeatures(t *testing.T) {
	payload, err := EncodeAdvertPayload(Advert{
		PublicKey: make([]byte, 32),
		NodeType:  AdvertNodeChat,
		Name:      "Plain",
	})
	if err != nil {
		t.Fatal(err)
	}
	out := CallJSON("decodeAdvert", `["`+hex.EncodeToString(payload)+`"]`)
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatal(err)
	}
	// Optional feature fields must be absent when the advert carries no features.
	for _, k := range []string{"feat1", "feat1Hex", "feat2", "feat2Hex"} {
		if _, ok := m[k]; ok {
			t.Errorf("expected %q to be absent, got %v", k, m[k])
		}
	}
}

func TestCallJSON_unknownOp(t *testing.T) {
	out := CallJSON("nope", `[]`)
	if !strings.Contains(out, `"error"`) {
		t.Fatalf("want error JSON, got %s", out)
	}
}
