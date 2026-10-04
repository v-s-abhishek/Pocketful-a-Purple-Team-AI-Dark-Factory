"""Shared request validation. Every endpoint that takes a body goes through
parse_json_object; every endpoint that takes an amount goes through
validate_amount. Do not parse bodies or amounts anywhere else."""

import json
import re
import unicodedata

MAX_BODY_BYTES = 16 * 1024
MIN_AMOUNT = 1
MAX_AMOUNT = 10**12
OWNER_MAX_LEN = 64


class RequestError(Exception):
    """A client error that maps to one HTTP status and one error code."""

    def __init__(self, status, code):
        super().__init__(code)
        self.status = status
        self.code = code


def invalid_json():
    return RequestError(400, "invalid_json")


def _reject_duplicate_keys(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError("duplicate key")
        obj[key] = value
    return obj


def _reject_constant(name):
    # Called for NaN, Infinity and -Infinity.
    raise ValueError("non-finite number")


def parse_json_object(raw):
    """Parse a request body. It must be <= 16 KiB of UTF-8 encoding a single
    JSON object with no duplicate keys and no NaN/Infinity. Anything else
    raises RequestError(400, 'invalid_json')."""
    if not isinstance(raw, (bytes, bytearray)) or len(raw) > MAX_BODY_BYTES:
        raise invalid_json()
    try:
        text = bytes(raw).decode("utf-8")
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, ValueError, RecursionError):
        # json.JSONDecodeError is a ValueError; so is an integer with more
        # digits than int_max_str_digits.
        raise invalid_json() from None
    if not isinstance(value, dict):
        raise invalid_json()
    return value


def validate_amount(value):
    """Return value if it is a JSON integer in [1, 10^12]; otherwise raise
    RequestError(400, 'invalid_amount'). Exact type check: bool (a subclass
    of int) and float (including 1.0 and 1e3) are rejected."""
    if type(value) is not int or not (MIN_AMOUNT <= value <= MAX_AMOUNT):
        raise RequestError(400, "invalid_amount")
    return value


# Cc: C0, DEL, C1 controls. Cf: invisible format characters (U+200B,
# U+202E, U+FEFF, tags such as U+E0001). Zl/Zp: U+2028, U+2029.
_REJECTED_OWNER_CATEGORIES = frozenset({"Cc", "Cf", "Zl", "Zp"})


def validate_owner(value):
    """Owner is a string of 1-64 characters, not whitespace-only, with no
    code point of Unicode category Cc, Cf, Zl or Zp, that can be stored as
    UTF-8 (a lone surrogate from a JSON \\ud800 escape cannot). Interior
    spaces are allowed. NUL matters most: SQLite's length() stops at it."""
    if type(value) is not str or not (1 <= len(value) <= OWNER_MAX_LEN):
        raise RequestError(400, "invalid_request")
    if value.strip() == "":
        raise RequestError(400, "invalid_request")
    if any(unicodedata.category(ch) in _REJECTED_OWNER_CATEGORIES for ch in value):
        raise RequestError(400, "invalid_request")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise RequestError(400, "invalid_request") from None
    return value


_ASCII_DIGITS = re.compile(r"[0-9]{1,7}")


def parse_header_int(value):
    """Parse a numeric header value: 1-7 ASCII digits only (surrounding
    whitespace allowed). Returns the int, or None if it is not one.
    str.isdigit() must not be used: it accepts Unicode digits like '²'."""
    if value is None:
        return None
    value = value.strip(" \t")
    if not _ASCII_DIGITS.fullmatch(value):
        return None
    return int(value)


def require_fields(body, allowed):
    """Reject any field not in `allowed`. Unknown fields are a client bug,
    not something to silently ignore in a money API."""
    extra = set(body) - set(allowed)
    if extra:
        raise RequestError(400, "invalid_request")
