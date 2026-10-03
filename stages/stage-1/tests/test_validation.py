"""Unit tests for the shared body parser, amount validator, owner validator
and token helpers (no server needed)."""

import json
import unittest

from app.tokens import hash_token, new_token, token_matches
from app.validation import (
    MAX_BODY_BYTES,
    RequestError,
    parse_header_int,
    parse_json_object,
    validate_amount,
    validate_owner,
)


def amount_from_json(text):
    """Parse an amount exactly the way a request body would be parsed."""
    return parse_json_object(('{"amount": %s}' % text).encode())["amount"]


class AmountValidatorTest(unittest.TestCase):
    def assertRejected(self, value):
        with self.assertRaises(RequestError) as ctx:
            validate_amount(value)
        self.assertEqual((ctx.exception.status, ctx.exception.code), (400, "invalid_amount"))

    def test_accepted(self):
        for value in (1, 2, 10**12):
            with self.subTest(value=value):
                self.assertIs(validate_amount(value), value)

    def test_rejected_python_values(self):
        for value in (0, -1, 10**12 + 1, 2**63, 2**64, 1.0, 1.5, 1e3, 0.1 + 0.2,
                      True, False, "100", None, [1], {"a": 1}, float("nan"),
                      float("inf")):
            with self.subTest(value=value):
                self.assertRejected(value)

    def test_rejected_after_json_parsing(self):
        # What actually arrives over the wire. -0 parses to int 0.
        for text in ("0", "-0", "-1", "1.0", "1.5", "1e3", "1E3", "0.30000000000000004",
                     "1000000000001", str(2**63), "true", "false", '"100"', "null",
                     "[1]", '{"n": 1}'):
            with self.subTest(text=text):
                self.assertRejected(amount_from_json(text))

    def test_accepted_after_json_parsing(self):
        self.assertEqual(validate_amount(amount_from_json("1")), 1)
        self.assertEqual(validate_amount(amount_from_json("1000000000000")), 10**12)


class JsonObjectParserTest(unittest.TestCase):
    def assertInvalid(self, raw):
        with self.assertRaises(RequestError) as ctx:
            parse_json_object(raw)
        self.assertEqual((ctx.exception.status, ctx.exception.code), (400, "invalid_json"))

    def test_valid_object(self):
        self.assertEqual(parse_json_object(b'{"owner": "a"}'), {"owner": "a"})
        self.assertEqual(parse_json_object(b"{}"), {})

    def test_rejected_bodies(self):
        cases = {
            "empty": b"",
            "whitespace": b"   ",
            "not json": b"owner=alice",
            "truncated": b'{"owner": "a"',
            "array": b'[{"owner": "a"}]',
            "scalar number": b"1",
            "scalar string": b'"a"',
            "null": b"null",
            "two objects": b'{"a": 1} {"b": 2}',
            "duplicate keys": b'{"amount": 1, "amount": 100}',
            "nested duplicate keys": b'{"x": {"a": 1, "a": 2}}',
            "NaN": b'{"amount": NaN}',
            "Infinity": b'{"amount": Infinity}',
            "-Infinity": b'{"amount": -Infinity}',
            "bad utf-8": b'{"owner": "\xff"}',
            "huge integer": ('{"amount": %s}' % ("9" * 5000)).encode(),
            "deep nesting": b'{"a":' * 100000 + b"1" + b"}" * 100000,
        }
        for name, raw in cases.items():
            with self.subTest(case=name):
                self.assertInvalid(raw)

    def test_size_boundary(self):
        exact = b'{"owner": "a"}'.ljust(MAX_BODY_BYTES, b" ")
        self.assertEqual(len(exact), MAX_BODY_BYTES)
        self.assertEqual(parse_json_object(exact), {"owner": "a"})
        self.assertInvalid(exact + b" ")

    def test_non_bytes_rejected(self):
        self.assertInvalid('{"owner": "a"}')


class OwnerValidatorTest(unittest.TestCase):
    def test_accepted(self):
        # Interior spaces (ASCII or not) are allowed.
        for value in ("a", "x" * 64, "Zoë", "名前", "a b", " a ", "a b", "a　b"):
            with self.subTest(value=value):
                self.assertEqual(validate_owner(value), value)

    def test_rejected(self):
        lone_surrogate = json.loads('"\\ud800"')
        for value in ("", "x" * 65, None, 1, True, ["a"], {"a": 1}, lone_surrogate):
            with self.subTest(value=value):
                with self.assertRaises(RequestError) as ctx:
                    validate_owner(value)
                self.assertEqual(ctx.exception.code, "invalid_request")

    def test_control_characters_rejected(self):
        # R1.1-A: every C0 control and DEL, alone, leading, inside, trailing.
        controls = [chr(c) for c in range(0x20)] + ["\x7f"]
        values = ["\x00" * 64]
        for ch in controls:
            values += [ch, ch + "abc", "a" + ch + "b", "x" * 63 + ch]
        for value in values:
            with self.subTest(value=value):
                with self.assertRaises(RequestError) as ctx:
                    validate_owner(value)
                self.assertEqual(ctx.exception.code, "invalid_request")

    def assertOwnerRejected(self, value):
        with self.assertRaises(RequestError) as ctx:
            validate_owner(value)
        self.assertEqual((ctx.exception.status, ctx.exception.code), (400, "invalid_request"))

    def test_whitespace_only_rejected(self):
        # 1.1c owner ruling: owner.strip() == "" with Unicode whitespace.
        for value in (" ", " " * 64, " ", "　", "  　 ", " "):
            with self.subTest(value=value):
                self.assertOwnerRejected(value)

    def test_invisible_and_separator_characters_rejected(self):
        # 1.1c owner ruling: categories Cc, Cf, Zl, Zp anywhere.
        for ch in ("​", "‮", " ", " ", "﻿", "\U000e0001",
                   "\x80", "\x9f", "­", "⁠"):
            for value in (ch, ch + "abc", "a" + ch + "b", "abc" + ch):
                with self.subTest(value=value):
                    self.assertOwnerRejected(value)


class HeaderIntTest(unittest.TestCase):
    def test_ascii_digits_only(self):
        # R1.1-B: str.isdigit() accepts these; the parser must not.
        for value in ("\xb2", "\xb9", "\xb3", "1\xb2", "١", "１", "+15", "-1",
                      "1e3", "1.0", "0x10", "", " ", "1 2", "12345678", None):
            with self.subTest(value=value):
                self.assertIsNone(parse_header_int(value))

    def test_accepted(self):
        for value, expected in (("0", 0), ("15", 15), ("015", 15), (" 16384 ", 16384),
                                ("9999999", 9999999)):
            with self.subTest(value=value):
                self.assertEqual(parse_header_int(value), expected)


class TokenTest(unittest.TestCase):
    def test_token_shape_and_uniqueness(self):
        tokens = {new_token() for _ in range(1000)}
        self.assertEqual(len(tokens), 1000)
        for token in list(tokens)[:10]:
            self.assertGreaterEqual(len(token), 43)  # 32 random bytes, base64url

    def test_hash_is_sha256_hex_and_not_the_token(self):
        token = new_token()
        digest = hash_token(token)
        self.assertRegex(digest, r"^[0-9a-f]{64}$")
        self.assertNotIn(token, digest)

    def test_matches(self):
        token = new_token()
        stored = hash_token(token)
        self.assertTrue(token_matches(stored, token))
        self.assertFalse(token_matches(stored, new_token()))
        self.assertFalse(token_matches(stored, ""))
        self.assertFalse(token_matches(stored, stored))  # the hash is not the token
        self.assertFalse(token_matches(stored, None))
        self.assertFalse(token_matches(stored, json.loads('"\\ud800"')))


if __name__ == "__main__":
    unittest.main()
