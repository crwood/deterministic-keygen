from deterministic_keygen import generate_phrase, derive_rsa_key_from_phrase


def test_generate_phrase_returns_12_words() -> None:
    phrase = generate_phrase()
    assert len(phrase.split()) == 12


def test_derive_rsa_key_from_phrase() -> None:
    phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    key1 = derive_rsa_key_from_phrase(phrase)
    key2 = derive_rsa_key_from_phrase(phrase)
    assert key1 == key2
