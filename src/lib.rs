use bip39::{Language, Mnemonic, MnemonicType};
use blake3;
use pyo3::prelude::*;
use pyo3::exceptions::{PyValueError, PyRuntimeError};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rsa::pkcs8::{EncodePrivateKey, LineEnding};
use rsa::RsaPrivateKey;
use std::str;
use anyhow::Error;

// As per the Blake3 docs <https://docs.rs/blake3/latest/blake3/fn.derive_key.html>:
// "The context string should be hardcoded, globally unique, and application-specific.
// A good default format for the context string is '[application] [commit timestamp]
// [purpose]':"
const RSA_CONTEXT: &str = "deterministic-keygen Wed 07 Feb 2024 11:50:00 AM EST RSA v1";

/// Generate a new BIP-39 mnemonic phrase.
#[pyfunction]
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
    match Mnemonic::from_phrase(phrase, Language::English) {
        Err(error) => Err(error),
        Ok(mnemonic) => {
            let entropy: &[u8] = mnemonic.entropy();
            Ok(entropy.to_vec())
        }
    }
}

#[test]
fn test_phrase_to_entropy() {
    let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let entropy = phrase_to_entropy(phrase).unwrap();
    let expected = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    assert_eq!(entropy, expected);
}

/// Derive an RSA key from a given vector of unsigned 8-bit integers.
// #[pyfunction]
pub fn derive_rsa_key(entropy: &Vec<u8>, bit_size: usize) -> Result<String, Error> {
    let seed: [u8; 32] = blake3::derive_key(RSA_CONTEXT, &entropy);
    let mut rng = ChaCha20Rng::from_seed(seed);
    match RsaPrivateKey::new(&mut rng, bit_size) {
        Err(error) => Err(error.into()),
        Ok(priv_key) => {
            match priv_key.to_pkcs8_pem(LineEnding::LF) {
                Err(error) => Err(error.into()),
                Ok(pem) => Ok(pem.to_string())
            }
        }
    }
}

#[test]
fn test_derive_rsa_key() {
    let phrase = generate_phrase();
    let entropy = phrase_to_entropy(&phrase).unwrap();
    let key1 = derive_rsa_key(&entropy, 512).unwrap();
    let key2 = derive_rsa_key(&entropy, 512).unwrap();
    assert_eq!(key1, key2);
}

/// Derive an RSA key from a given BIP-39 mnemonic phrase.
#[pyfunction]
#[pyo3(signature = (phrase, bit_size = 2048))]
pub fn derive_rsa_key_from_phrase(phrase: &str, bit_size: usize) -> PyResult<String> {
    match phrase_to_entropy(phrase) {
        Err(error) => Err(PyValueError::new_err(error.to_string())),
        Ok(entropy) => {
            match derive_rsa_key(&entropy, bit_size) {
                Err(error) => Err(PyRuntimeError::new_err(error.to_string())),
                Ok(key) => Ok(key),
            }
        }
    }
}

/// Deterministic key-generator.
#[pymodule]
fn deterministic_keygen(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(generate_phrase, m)?)?;
    m.add_function(wrap_pyfunction!(derive_rsa_key_from_phrase, m)?)?;
    Ok(())
}
