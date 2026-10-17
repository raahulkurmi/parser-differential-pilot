# TEST-ONLY KEYS - DO NOT USE FOR ANYTHING ELSE

`TEST_ONLY_rs256_private.pem` / `TEST_ONLY_rs256_public.pem` are a throwaway
RSA-2048 key pair generated for this repository. The private key is published
deliberately so that anyone can rebuild and re-verify the corpus tokens. It
protects nothing and must never be trusted by any system.

Generated with OpenSSL 3.0.18:

```
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out TEST_ONLY_rs256_private.pem
openssl pkey -in TEST_ONLY_rs256_private.pem -pubout -out TEST_ONLY_rs256_public.pem
```

The tokens in `corpus/tokens/` are signed with RS256 (RSASSA-PKCS1-v1_5 with
SHA-256), which is deterministic, so `scripts/build_tokens.py` reproduces them
byte for byte.
