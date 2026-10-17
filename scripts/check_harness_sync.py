"""Fail if the two copies of the Go canonical-encoding file have diverged."""

import sys

with open("harness/go/canon.go", "rb") as a, open("harness/go-opa/canon.go", "rb") as b:
    if a.read() != b.read():
        sys.exit("harness/go/canon.go and harness/go-opa/canon.go differ")
print("canon.go copies identical")
