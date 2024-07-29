use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyBytes;

mod phrase;
use crate::phrase::{generate_phrase, phrase_to_entropy};

mod rsa;
use crate::rsa::derive_rsa_key;

/// Generate a new BIP-39 mnemonic phrase.
#[pyfunction]
#[pyo3(name = "generate_phrase")]
pub fn py_generate_phrase() -> String {
    generate_phrase()
}

/// Derive an RSA key from a given sequence of bytes.
#[pyfunction]
#[pyo3(name = "derive_rsa_key")]
#[pyo3(signature = (entropy, bit_size = 2048))]
pub fn py_derive_rsa_key(entropy: &PyBytes, bit_size: usize) -> PyResult<String> {
    match derive_rsa_key(&Vec::from(entropy.as_bytes()), bit_size) {
        Err(error) => Err(PyRuntimeError::new_err(error.to_string())),
        Ok(key) => Ok(key),
    }
}

/// Derive an RSA key from a given BIP-39 mnemonic phrase.
#[pyfunction]
#[pyo3(signature = (phrase, bit_size = 2048))]
pub fn derive_rsa_key_from_phrase(phrase: &str, bit_size: usize) -> PyResult<String> {
    let entropy = match phrase_to_entropy(phrase) {
        Err(error) => return Err(PyValueError::new_err(error.to_string())),
        Ok(entropy) => entropy,
    };
    match derive_rsa_key(&entropy, bit_size) {
        Err(error) => Err(PyRuntimeError::new_err(error.to_string())),
        Ok(key) => Ok(key),
    }
}

/// Deterministic key-generator.
#[pymodule]
fn deterministic_keygen(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(py_generate_phrase, m)?)?;
    m.add_function(wrap_pyfunction!(py_derive_rsa_key, m)?)?;
    m.add_function(wrap_pyfunction!(derive_rsa_key_from_phrase, m)?)?;
    Ok(())
}
