// Canonical value encoding shared by every harness (see docs/PREREGISTRATION.md §5.2).
// This file is duplicated verbatim in harness/go/canon.go and harness/go-opa/canon.go; scripts/check_harness_sync.py
// verifies that the two copies are identical.
package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"unicode/utf8"
)

// Fields are the five security-relevant claims, in report order.
var Fields = []string{"iss", "sub", "aud", "exp", "iat"}

// Absent is the canonical marker for a field the parser did not expose.
var Absent = map[string]any{"t": "absent"}

// Canon converts a decoded Go value into the canonical typed form.
func Canon(v any) any {
	switch x := v.(type) {
	case nil:
		return map[string]any{"t": "null"}
	case bool:
		return map[string]any{"t": "bool", "v": x}
	case string:
		return canonString(x)
	case float64:
		return map[string]any{"t": "number", "kind": "f64", "bits": fmt.Sprintf("%016x", math.Float64bits(x))}
	case float32:
		return Canon(float64(x))
	case int:
		return canonInt(big.NewInt(int64(x)))
	case int64:
		return canonInt(big.NewInt(x))
	case uint64:
		return canonInt(new(big.Int).SetUint64(x))
	case json.Number:
		return map[string]any{"t": "number", "kind": "decimal", "v": string(x)}
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = Canon(e)
		}
		return map[string]any{"t": "array", "v": out}
	case []string:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = canonString(e)
		}
		return map[string]any{"t": "array", "v": out}
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		pairs := make([]any, 0, len(keys))
		for _, k := range keys {
			pairs = append(pairs, []any{canonString(k), Canon(x[k])})
		}
		return map[string]any{"t": "object", "v": pairs}
	default:
		return map[string]any{"t": "other", "v": fmt.Sprintf("%T:%v", v, v)}
	}
}

func canonInt(n *big.Int) any {
	return map[string]any{"t": "number", "kind": "int", "v": n.String()}
}

// canonString emits Unicode scalar values; a byte that is not valid UTF-8 is
// emitted as -(byte+1) so that no information is lost.
func canonString(s string) any {
	cps := []int{}
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			cps = append(cps, -(int(s[i]) + 1))
		} else {
			cps = append(cps, int(r))
		}
		i += size
	}
	return map[string]any{"t": "string", "cp": cps}
}

// Record is one (case, parser) observation; one JSON line in results/raw/<parser>.jsonl.
type Record struct {
	Schema  int            `json:"schema"`
	Case    string         `json:"case"`
	Parser  string         `json:"parser"`
	Outcome string         `json:"outcome"`
	Error   *string        `json:"error"`
	Fields  map[string]any `json:"fields"`
}

func Accept(caseID, parser string, fields map[string]any) Record {
	return Record{Schema: 1, Case: caseID, Parser: parser, Outcome: "ACCEPT", Fields: fields}
}

func Reject(caseID, parser string, err error) Record {
	msg := err.Error()
	return Record{Schema: 1, Case: caseID, Parser: parser, Outcome: "REJECT", Error: &msg, Fields: nil}
}

// FieldsFromMap extracts the five fields from a decoded claims object (raw-map parsers).
func FieldsFromMap(m map[string]any) map[string]any {
	out := map[string]any{}
	for _, f := range Fields {
		if v, ok := m[f]; ok {
			out[f] = Canon(v)
		} else {
			out[f] = Absent
		}
	}
	return out
}

// CaseIDs reads the case ids, in manifest order, from <corpus>/MANIFEST.csv.
func CaseIDs(corpus string) ([]string, error) {
	f, err := os.Open(filepath.Join(corpus, "MANIFEST.csv"))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	rows, err := csv.NewReader(f).ReadAll()
	if err != nil {
		return nil, err
	}
	ids := []string{}
	for _, r := range rows[1:] {
		ids = append(ids, r[0])
	}
	return ids, nil
}

// PayloadPath and TokenPath give the on-disk inputs for a case.
func PayloadPath(corpus, id string) string { return filepath.Join(corpus, id+".json") }
func TokenPath(corpus, id string) string   { return filepath.Join(corpus, "tokens", id+".jwt") }

func Emit(enc *json.Encoder, r Record) {
	if err := enc.Encode(r); err != nil {
		fmt.Fprintln(os.Stderr, "emit:", err)
		os.Exit(2)
	}
}
