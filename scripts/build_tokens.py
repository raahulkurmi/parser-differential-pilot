"""Write corpus/tokens/<id>.jwt: one RS256-signed JWS per corpus payload.

Construction (docs/PREREGISTRATION.md section 3.3):
  header  = the fixed bytes {"alg":"RS256","typ":"JWT"}
  payload = the corpus file's bytes, unchanged (never parsed)
  token   = b64url(header) "." b64url(payload) "." b64url(RS256(b64url(header) "." b64url(payload)))
  b64url  = RFC 4648 section 5 alphabet, no padding
The file holds the token followed by a single LF.

RSASSA-PKCS1-v1_5 is deterministic, so re-running this script reproduces the
tokens byte for byte.

Usage: harness/python/.venv/bin/python scripts/build_tokens.py   (from the repository root)
"""

import base64
import csv
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

HEADER = b'{"alg":"RS256","typ":"JWT"}'
KEY = "testdata/keys/TEST_ONLY_rs256_private.pem"


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=")


def main():
    with open(KEY, "rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=None)
    with open("corpus/MANIFEST.csv", newline="", encoding="utf-8") as f:
        ids = [row["id"] for row in csv.DictReader(f)]
    os.makedirs("corpus/tokens", exist_ok=True)
    for cid in ids:
        with open(os.path.join("corpus", cid + ".json"), "rb") as f:
            payload = f.read()
        signing_input = b64url(HEADER) + b"." + b64url(payload)
        sig = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        with open(os.path.join("corpus", "tokens", cid + ".jwt"), "wb") as f:
            f.write(signing_input + b"." + b64url(sig) + b"\n")
    print(f"wrote {len(ids)} tokens")


if __name__ == "__main__":
    main()
