// Go harness: go-encjson-struct, go-golangjwt, go-gojose.
//
// Usage: harness-go -parser <id> -corpus <dir> -pubkey <pem>  (JSONL on stdout)
package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	josejwt "gopkg.in/go-jose/go-jose.v2/jwt"
)

// claimsStruct is how Go code typically consumes claims with encoding/json:
// a struct with tagged fields. json.RawMessage keeps "absent" (nil) distinct
// from an explicit JSON null (RawMessage("null")).
type claimsStruct struct {
	Iss json.RawMessage `json:"iss"`
	Sub json.RawMessage `json:"sub"`
	Aud json.RawMessage `json:"aud"`
	Exp json.RawMessage `json:"exp"`
	Iat json.RawMessage `json:"iat"`
}

func encjsonStruct(data []byte) (map[string]any, error) {
	var c claimsStruct
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	out := map[string]any{}
	for name, raw := range map[string]json.RawMessage{"iss": c.Iss, "sub": c.Sub, "aud": c.Aud, "exp": c.Exp, "iat": c.Iat} {
		if raw == nil {
			out[name] = Absent
			continue
		}
		var v any
		if err := json.Unmarshal(raw, &v); err != nil {
			return nil, fmt.Errorf("re-decode %s: %w", name, err)
		}
		out[name] = Canon(v)
	}
	return out, nil
}

func golangJWT(token string, pub *rsa.PublicKey) (map[string]any, error) {
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(token, claims, func(*jwt.Token) (any, error) { return pub, nil },
		jwt.WithValidMethods([]string{"RS256"}), jwt.WithoutClaimsValidation())
	if err != nil {
		return nil, err
	}
	return FieldsFromMap(claims), nil
}

// goJose decodes into the typed jwt.Claims struct, as Kubernetes does.
// The typed struct cannot distinguish "" from absent for iss/sub; both are ABSENT.
func goJose(token string, pub *rsa.PublicKey) (map[string]any, error) {
	tok, err := josejwt.ParseSigned(token)
	if err != nil {
		return nil, err
	}
	var c josejwt.Claims
	if err := tok.Claims(pub, &c); err != nil {
		return nil, err
	}
	str := func(s string) any {
		if s == "" {
			return Absent
		}
		return Canon(s)
	}
	date := func(d *josejwt.NumericDate) any {
		if d == nil {
			return Absent
		}
		return Canon(int64(*d))
	}
	aud := any(Absent)
	if c.Audience != nil {
		aud = Canon([]string(c.Audience))
	}
	return map[string]any{"iss": str(c.Issuer), "sub": str(c.Subject), "aud": aud, "exp": date(c.Expiry), "iat": date(c.IssuedAt)}, nil
}

func loadPub(path string) (*rsa.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("no PEM block")
	}
	k, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := k.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA key")
	}
	return pub, nil
}

func main() {
	parser := flag.String("parser", "", "go-encjson-struct | go-golangjwt | go-gojose")
	corpus := flag.String("corpus", "corpus", "corpus directory")
	pubPath := flag.String("pubkey", "testdata/keys/TEST_ONLY_rs256_public.pem", "RS256 public key")
	flag.Parse()

	ids, err := CaseIDs(*corpus)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	pub, err := loadPub(*pubPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	enc := json.NewEncoder(os.Stdout)
	for _, id := range ids {
		var fields map[string]any
		var perr error
		switch *parser {
		case "go-encjson-struct":
			data, err := os.ReadFile(PayloadPath(*corpus, id))
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(2)
			}
			fields, perr = encjsonStruct(data)
		case "go-golangjwt", "go-gojose":
			tb, err := os.ReadFile(TokenPath(*corpus, id))
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(2)
			}
			token := strings.TrimSpace(string(tb))
			if *parser == "go-golangjwt" {
				fields, perr = golangJWT(token, pub)
			} else {
				fields, perr = goJose(token, pub)
			}
		default:
			fmt.Fprintln(os.Stderr, "unknown parser", *parser)
			os.Exit(2)
		}
		if perr != nil {
			Emit(enc, Reject(id, *parser, perr))
		} else {
			Emit(enc, Accept(id, *parser, fields))
		}
	}
}
