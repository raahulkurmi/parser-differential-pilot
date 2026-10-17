// OPA (policy-side) harness: go-opa-json, go-opa-jwt.
//
// Kept in its own Go module so that OPA's dependency graph cannot change the
// versions pinned for the verifier-side Go libraries in harness/go.
//
// Usage: harness-go-opa -parser <id> -corpus <dir> -pubkey <pem>  (JSONL on stdout)
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/open-policy-agent/opa/v1/rego"
)

// A policy that receives raw JSON and decodes it with the json.unmarshal builtin.
const queryJSON = `x := json.unmarshal(input.raw); is_object(x)`

// A policy that verifies the RS256 signature, then reads the claims with io.jwt.decode.
const queryJWT = `io.jwt.verify_rs256(input.token, input.cert) == true; [_, x, _] := io.jwt.decode(input.token)`

func eval(query string, input map[string]any) (map[string]any, error) {
	rs, err := rego.New(rego.Query(query), rego.Input(input), rego.StrictBuiltinErrors(true)).Eval(context.Background())
	if err != nil {
		return nil, err
	}
	if len(rs) == 0 {
		return nil, errors.New("query undefined")
	}
	obj, ok := rs[0].Bindings["x"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("claims not an object: %T", rs[0].Bindings["x"])
	}
	return obj, nil
}

func main() {
	parser := flag.String("parser", "", "go-opa-json | go-opa-jwt")
	corpus := flag.String("corpus", "corpus", "corpus directory")
	pubPath := flag.String("pubkey", "testdata/keys/TEST_ONLY_rs256_public.pem", "RS256 public key (PEM)")
	flag.Parse()

	ids, err := CaseIDs(*corpus)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	cert, err := os.ReadFile(*pubPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	enc := json.NewEncoder(os.Stdout)
	for _, id := range ids {
		var claims map[string]any
		var perr error
		switch *parser {
		case "go-opa-json":
			data, err := os.ReadFile(PayloadPath(*corpus, id))
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(2)
			}
			claims, perr = eval(queryJSON, map[string]any{"raw": string(data)})
		case "go-opa-jwt":
			tb, err := os.ReadFile(TokenPath(*corpus, id))
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(2)
			}
			claims, perr = eval(queryJWT, map[string]any{"token": strings.TrimSpace(string(tb)), "cert": string(cert)})
		default:
			fmt.Fprintln(os.Stderr, "unknown parser", *parser)
			os.Exit(2)
		}
		if perr != nil {
			Emit(enc, Reject(id, *parser, perr))
		} else {
			Emit(enc, Accept(id, *parser, FieldsFromMap(claims)))
		}
	}
}
