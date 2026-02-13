package canonical

import "testing"

func TestMarshalRawJSONDeterministicAcrossEquivalentPayloads(t *testing.T) {
	inputA := []byte(`{"b":2,"a":[3,{"d":4,"c":5}],"z":"x"}`)
	inputB := []byte(`{ "z":"x", "a":[3,{"c":5,"d":4}], "b":2 }`)

	canonicalA, err := MarshalRawJSON(inputA)
	if err != nil {
		t.Fatalf("marshal inputA: %v", err)
	}
	canonicalB, err := MarshalRawJSON(inputB)
	if err != nil {
		t.Fatalf("marshal inputB: %v", err)
	}

	expected := `{"a":[3,{"c":5,"d":4}],"b":2,"z":"x"}`
	if string(canonicalA) != expected {
		t.Fatalf("unexpected canonical output for inputA: %s", string(canonicalA))
	}
	if string(canonicalB) != expected {
		t.Fatalf("unexpected canonical output for inputB: %s", string(canonicalB))
	}
}

func TestMarshalProducesStableOutput(t *testing.T) {
	payload := map[string]any{
		"nested": map[string]any{
			"delta": 4,
			"alpha": 1,
		},
		"array": []any{map[string]any{"b": 2, "a": 1}, "ok"},
	}

	var first string
	for i := 0; i < 25; i++ {
		canonical, err := Marshal(payload)
		if err != nil {
			t.Fatalf("marshal payload: %v", err)
		}
		if i == 0 {
			first = string(canonical)
			continue
		}
		if string(canonical) != first {
			t.Fatalf("marshal output changed between runs: %s != %s", string(canonical), first)
		}
	}
}

func TestMarshalRawJSONInvalidInput(t *testing.T) {
	if _, err := MarshalRawJSON([]byte(`{"a":`)); err == nil {
		t.Fatal("expected error for invalid json input")
	}
}
