"""Account tokens. The raw token is shown once at creation; only its
SHA-256 hex digest is stored."""

import hashlib
import hmac
import secrets


def new_token():
    return secrets.token_urlsafe(32)


def hash_token(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def token_matches(stored_hash, presented):
    """Constant-time check of a presented token against a stored hash.
    Any non-str or non-encodable input is simply a mismatch."""
    if type(presented) is not str or type(stored_hash) is not str:
        return False
    try:
        candidate = hash_token(presented)
    except UnicodeEncodeError:
        return False
    return hmac.compare_digest(candidate.encode("ascii"), stored_hash.encode("ascii"))
