//! Rust harness: rs-serdejson, rs-jsonwebtoken.
//!
//! Usage: pdp-rust-harness --parser <id> --corpus <dir> --pubkey <pem>   (JSONL on stdout)
//! Canonical value encoding: docs/PREREGISTRATION.md section 5.2.

use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::process::exit;

use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use serde_json::{Map, Value, json};

const FIELDS: [&str; 5] = ["iss", "sub", "aud", "exp", "iat"];

fn canon(v: &Value) -> Value {
    match v {
        Value::Null => json!({"t": "null"}),
        Value::Bool(b) => json!({"t": "bool", "v": b}),
        Value::String(s) => json!({"t": "string", "cp": s.chars().map(|c| c as u32).collect::<Vec<_>>()}),
        Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                json!({"t": "number", "kind": "int", "v": u.to_string()})
            } else if let Some(i) = n.as_i64() {
                json!({"t": "number", "kind": "int", "v": i.to_string()})
            } else if let Some(f) = n.as_f64() {
                json!({"t": "number", "kind": "f64", "bits": format!("{:016x}", f.to_bits())})
            } else {
                json!({"t": "other", "v": format!("number:{n}")})
            }
        }
        Value::Array(a) => json!({"t": "array", "v": a.iter().map(canon).collect::<Vec<_>>()}),
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            let pairs: Vec<Value> = keys.into_iter().map(|k| json!([canon(&Value::String(k.clone())), canon(&m[k])])).collect();
            json!({"t": "object", "v": pairs})
        }
    }
}

fn fields_from_map(m: &Map<String, Value>) -> Value {
    let mut out = Map::new();
    for f in FIELDS {
        out.insert(f.to_string(), m.get(f).map(canon).unwrap_or_else(|| json!({"t": "absent"})));
    }
    Value::Object(out)
}

fn rs_serdejson(data: &[u8]) -> Result<Value, String> {
    let v: Value = serde_json::from_slice(data).map_err(|e| e.to_string())?;
    match v {
        Value::Object(m) => Ok(fields_from_map(&m)),
        _ => Err("top-level value is not an object".into()),
    }
}

/// Signature verified; every optional claim check jsonwebtoken exposes is disabled.
fn rs_jsonwebtoken(token: &str, key: &DecodingKey) -> Result<Value, String> {
    let mut v = Validation::new(Algorithm::RS256);
    v.required_spec_claims = HashSet::new();
    v.validate_exp = false;
    v.validate_nbf = false;
    v.validate_aud = false;
    v.leeway = 0;
    let data = decode::<Map<String, Value>>(token, key, &v).map_err(|e| format!("{e:?}"))?;
    Ok(fields_from_map(&data.claims))
}

fn arg(args: &[String], name: &str, dflt: &str) -> String {
    args.iter()
        .position(|a| a == &format!("--{name}"))
        .and_then(|i| args.get(i + 1).cloned())
        .unwrap_or_else(|| dflt.to_string())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let parser = arg(&args, "parser", "");
    let corpus = arg(&args, "corpus", "corpus");
    let pubkey = arg(&args, "pubkey", "testdata/keys/TEST_ONLY_rs256_public.pem");
    if parser != "rs-serdejson" && parser != "rs-jsonwebtoken" {
        eprintln!("unknown parser {parser}");
        exit(2);
    }
    let pem = fs::read(&pubkey).unwrap_or_else(|e| {
        eprintln!("{e}");
        exit(2)
    });
    let key = DecodingKey::from_rsa_pem(&pem).unwrap_or_else(|e| {
        eprintln!("{e}");
        exit(2)
    });
    let manifest = fs::read_to_string(Path::new(&corpus).join("MANIFEST.csv")).unwrap_or_else(|e| {
        eprintln!("{e}");
        exit(2)
    });
    for line in manifest.lines().skip(1).filter(|l| !l.is_empty()) {
        let id = line.split(',').next().unwrap();
        let result = if parser == "rs-serdejson" {
            let data = fs::read(Path::new(&corpus).join(format!("{id}.json"))).unwrap_or_else(|e| {
                eprintln!("{e}");
                exit(2)
            });
            rs_serdejson(&data)
        } else {
            let tok = fs::read_to_string(Path::new(&corpus).join("tokens").join(format!("{id}.jwt"))).unwrap_or_else(|e| {
                eprintln!("{e}");
                exit(2)
            });
            rs_jsonwebtoken(tok.trim(), &key)
        };
        let rec = match result {
            Ok(fields) => json!({"schema": 1, "case": id, "parser": parser, "outcome": "ACCEPT", "error": null, "fields": fields}),
            Err(e) => json!({"schema": 1, "case": id, "parser": parser, "outcome": "REJECT", "error": e, "fields": null}),
        };
        println!("{rec}");
    }
}
