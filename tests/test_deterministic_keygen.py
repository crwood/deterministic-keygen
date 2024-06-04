import pytest

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
