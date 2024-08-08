from pathlib import Path

import pytest
import yaml

from allmydata.util.base32 import b2a
from allmydata.util.hashutil import (
    _SHA256d_Hasher,  # XXX
    ssk_pubkey_fingerprint_hash,
    ssk_writekey_hash,
)
from cryptography.hazmat.primitives import serialization
from deterministic_keygen import (
    generate_phrase,
    derive_rsa_key,
    derive_rsa_key_from_phrase,
)


def test_generate_phrase_returns_12_words() -> None:
    phrase = generate_phrase()
    assert len(phrase.split()) == 12


def test_derive_rsa_key():
    entropy = b'\x00' * 32
    key1 = derive_rsa_key(entropy)
    key2 = derive_rsa_key(entropy)
    assert key1 == key2


@pytest.mark.parametrize("phrase, msg", [
    ("abandon", "invalid number of words in phrase: 1"),
    ("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon notaword", "invalid word in phrase"),
    ("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon", "invalid checksum"),
])
def test_derive_rsa_key_from_phrase_raises_value_error(phrase, msg) -> None:
    with pytest.raises(ValueError) as excinfo:
        derive_rsa_key_from_phrase(phrase)
    assert str(excinfo.value) == msg


def test_derive_rsa_key_from_phrase() -> None:
    phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    key1 = derive_rsa_key_from_phrase(phrase)
    key2 = derive_rsa_key_from_phrase(phrase)
    assert key1 == key2


@pytest.mark.parametrize("data, expected", [
    (b"", b"lx3obytwcnm5gcucoucy4km7zqbycu2fix2vz5b6igmd6xkmsrla"),
    (b"test", b"svgvusp5odm3rpg3gxjfejtyfgkx67xx7jwhj6eedg64l2bcbh2a"),
])
def test_sha256d(data, expected) -> None:
    hasher = _SHA256d_Hasher()
    hasher.update(data)
    digest = hasher.digest()
    assert b2a(digest) == expected


def derive_lafs_mutable(private_key_pem: str, format: str) -> str:
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode(),
        password=None,
    )
    public_key = private_key.public_key()

    privkey_der_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pubkey_der_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    writekey = b2a(ssk_writekey_hash(privkey_der_bytes)).decode()
    fingerprint = b2a(ssk_pubkey_fingerprint_hash(pubkey_der_bytes)).decode()

    return f"URI:{format}:{writekey}:{fingerprint}"


def test_derive_lafs_mutable() -> None:
    with open(Path(__file__).parent.parent / "lafs" / "tests" / "vectors" / "lafs.yaml") as f:
        data = yaml.safe_load(f)
    for vector in data["vector"]:
        kind = vector["format"]["kind"]
        if kind == "ssk":
            key = vector["format"]["params"]["key"]
            print(key)
            expected = vector["expected"]
            parts = expected.split(":")
            writekey = parts[2]
            fingerprint = parts[3]
            print(expected, writekey, fingerprint)
    assert False, "Not yet implemented"
