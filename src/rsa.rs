use anyhow::Error;
use blake3;
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng;
use rsa::RsaPrivateKey;
use rsa::pkcs8::{EncodePrivateKey, LineEnding};
use std::str;

// As per the Blake3 docs <https://docs.rs/blake3/latest/blake3/fn.derive_key.html>:
// "The context string should be hardcoded, globally unique, and application-specific.
// A good default format for the context string is '[application] [commit timestamp]
// [purpose]':"
const RSA_CONTEXT: &str = "deterministic-keygen Wed 07 Feb 2024 11:50:00 AM EST RSA v1";

/// Derive an RSA key from a given vector of unsigned 8-bit integers.
pub fn derive_rsa_key(entropy: &Vec<u8>, bit_size: usize) -> Result<String, Error> {
    let seed: [u8; 32] = blake3::derive_key(RSA_CONTEXT, &entropy);
    let mut rng = ChaCha20Rng::from_seed(seed);
    let priv_key = RsaPrivateKey::new(&mut rng, bit_size)?;
    let pem = priv_key.to_pkcs8_pem(LineEnding::LF)?;
    Ok(pem.to_string())
}

#[cfg(test)]
mod tests {
    use rand::Rng;
    use crate::rsa::derive_rsa_key;

    #[test]
    fn test_derive_rsa_key() {
        let entropy = rand::thread_rng().gen::<[u8; 32]>().to_vec();
        let key1 = derive_rsa_key(&entropy, 512).unwrap();
        let key2 = derive_rsa_key(&entropy, 512).unwrap();
        assert_eq!(key1, key2);
    }
}
