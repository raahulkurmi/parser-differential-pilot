"""Unit tests for the pre-registered equality and classification rules.

Uses hand-written synthetic records only; never reads the corpus or results.
Usage: python3 -m unittest discover -s tests
"""

import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

from pdp_common import ACCEPTANCE, AGREE, BOTH_REJECT, VALUE, classify, norm  # noqa: E402

ABS = {"t": "absent"}


def s(text):
    return {"t": "string", "cp": [ord(c) for c in text]}


def i(n):
    return {"t": "number", "kind": "int", "v": str(n)}


def f64(x):
    return {"t": "number", "kind": "f64", "bits": struct.pack(">d", x).hex()}


def dec(text):
    return {"t": "number", "kind": "decimal", "v": text}


def rec(**fields):
    base = {"iss": s("i"), "sub": s("s"), "aud": s("a"), "exp": i(10), "iat": i(1)}
    base.update(fields)
    return {"outcome": "ACCEPT", "fields": base}


REJ = {"outcome": "REJECT", "fields": None}


class Numbers(unittest.TestCase):
    def test_exponent_equals_integer(self):
        self.assertEqual(norm(f64(1e9)), norm(i(1000000000)))
        self.assertEqual(norm(dec("1E9")), norm(i(1000000000)))

    def test_float_rounding_is_a_difference(self):
        self.assertNotEqual(norm(f64(float(2**53 + 1))), norm(i(2**53 + 1)))

    def test_exact_decimal_vs_nearest_double(self):
        self.assertNotEqual(norm(dec("0.1")), norm(f64(0.1)))

    def test_negative_zero(self):
        self.assertEqual(norm(f64(-0.0)), norm(i(0)))

    def test_specials(self):
        self.assertEqual(norm(f64(float("inf"))), ("num", "inf"))
        self.assertEqual(norm(f64(float("nan"))), norm(f64(-float("nan"))))
        self.assertNotEqual(norm(dec("1e400")), norm(f64(float("inf"))))

    def test_type_matters(self):
        self.assertNotEqual(norm(s("123")), norm(i(123)))
        self.assertNotEqual(norm({"t": "null"}), norm(ABS))


class Classification(unittest.TestCase):
    def test_agree_and_aud_rule(self):
        a, b = rec(), rec(aud={"t": "array", "v": [s("a")]})
        self.assertEqual(classify(a, b, "rfc")[0], AGREE)
        cls, diffs = classify(a, b, "strict")
        self.assertEqual(cls, VALUE)
        self.assertEqual(diffs[0]["field"], "aud")

    def test_value_with_absent_side(self):
        cls, diffs = classify(rec(), rec(sub=ABS))
        self.assertEqual(cls, VALUE)
        self.assertEqual(diffs, [{"field": "sub", "a_absent": False, "b_absent": True}])

    def test_acceptance_and_both_reject(self):
        self.assertEqual(classify(rec(), REJ)[0], ACCEPTANCE)
        self.assertEqual(classify(REJ, REJ)[0], BOTH_REJECT)

    def test_strings_are_code_point_exact(self):
        self.assertEqual(classify(rec(iss=s("a\ud800")), rec(iss=s("a�")))[0], VALUE)


if __name__ == "__main__":
    unittest.main()
