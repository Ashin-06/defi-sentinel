"""Keccak-256 (Ethereum's hash, original padding, not NIST SHA3-256), from pycryptodome (pycryptodomex, the Cryptodome namespace).
Used to derive 4-byte function selectors from signatures instead of hard-coding them."""
from __future__ import annotations

from Cryptodome.Hash import keccak


def keccak256(data: bytes) -> bytes:
    return keccak.new(digest_bits=256, data=data).digest()


def selector(signature: str) -> str:
    return "0x" + keccak256(signature.encode()).hex()[:8]
