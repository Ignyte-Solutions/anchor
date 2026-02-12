package canonical_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ignyte-solutions/ignyte-anchor/internal/canonical"
)

func TestMarshalRawJSONCanonicalizesNestedObjects(t *testing.T) {
	input := []byte(`{"b":2,"a":{"d":4,"c":3},"arr":[{"z":1,"y":2},true,null]}`)

	got, err := canonical.MarshalRawJSON(input)
	if err != nil {
		t.Fatalf("marshal canonical json: %v", err)
	}

	want := `{"a":{"c":3,"d":4},"arr":[{"y":2,"z":1},true,null],"b":2}`
	if string(got) != want {
		t.Fatalf("unexpected canonical json\nwant=%s\ngot=%s", want, string(got))
	}
}

func TestMarshalRawJSONEquivalentPayloadsMatch(t *testing.T) {
	left := []byte(`{"z":1,"a":{"k2":"v2","k1":"v1"},"arr":[3,2,1]}`)
	right := []byte(`{
		"arr": [3,2,1],
		"a": {"k1":"v1", "k2":"v2"},
		"z": 1
	}`)

	leftCanonical, err := canonical.MarshalRawJSON(left)
	if err != nil {
		t.Fatalf("canonicalize left payload: %v", err)
	}
	rightCanonical, err := canonical.MarshalRawJSON(right)
	if err != nil {
		t.Fatalf("canonicalize right payload: %v", err)
	}

	if !bytes.Equal(leftCanonical, rightCanonical) {
		t.Fatalf("expected equivalent payloads to canonicalize equally\nleft=%s\nright=%s", string(leftCanonical), string(rightCanonical))
	}
}

func TestMarshalRawJSONRejectsInvalidJSON(t *testing.T) {
	_, err := canonical.MarshalRawJSON([]byte(`{"a":`))
	if err == nil {
		t.Fatal("expected parse error for invalid JSON")
	}
	if !strings.Contains(err.Error(), "decode JSON") {
		t.Fatalf("expected decode JSON error, got %v", err)
	}
}
