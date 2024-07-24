use anyhow::Error;
use bip39::{Language, Mnemonic, MnemonicType};

/// Generate a new BIP-39 mnemonic phrase.
pub fn generate_phrase() -> String {
    Mnemonic::new(MnemonicType::Words12, Language::English)
        .phrase()
        .to_string()
}

#[test]
fn test_generate_phrase_returns_12_words() {
    let phrase = generate_phrase();
    assert_eq!(phrase.split_whitespace().count(), 12);
}

/// Convert a BIP-39 mnemonic phrase to its corresponding entropy.
pub fn phrase_to_entropy(phrase: &str) -> Result<Vec<u8>, Error> {
    let mnemonic = Mnemonic::from_phrase(phrase, Language::English)?;
    let entropy: &[u8] = mnemonic.entropy();
    Ok(entropy.to_vec())
}

#[test]
fn test_phrase_to_entropy() {
    let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let entropy = phrase_to_entropy(phrase).unwrap();
    let expected = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    assert_eq!(entropy, expected);
}
