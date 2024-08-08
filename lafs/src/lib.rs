use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};
use rsa::RsaPrivateKey;

mod base32;
mod hashutil;
mod netstring;

fn derive_lafs_mutable(private_key_pem: &str, format: &str) -> String {
    // TODO: Support pkcs8?
    let private_key = RsaPrivateKey::from_pkcs1_pem(private_key_pem).unwrap();
    let public_key = private_key.to_public_key();

    let privkey_der = private_key.to_pkcs8_der().unwrap();
    let privkey_der_bytes = privkey_der.as_bytes();

    let pubkey_der = public_key.to_public_key_der().unwrap();
    let pubkey_der_bytes = pubkey_der.as_bytes();

    let writekey = hashutil::ssk_writekey_hash(privkey_der_bytes);
    let fingerprint = hashutil::ssk_pubkey_fingerprint_hash(pubkey_der_bytes);

    let writekey_b32 = base32::b2a(&writekey);
    let fingerprint_b32 = base32::b2a(&fingerprint);

    let writekey_b32_str = String::from_utf8(writekey_b32).unwrap();
    let fingerprint_b32_str = String::from_utf8(fingerprint_b32).unwrap();

    format!(
        "URI:{}:{}:{}",
        format, writekey_b32_str, fingerprint_b32_str
    )
}

#[cfg(test)]
mod tests {
    use serde_yaml;

    #[test]
    fn test_derive_lafs_mutable() {
        let contents = std::fs::read_to_string("tests/vectors/lafs.yaml").unwrap();
        let data: serde_yaml::Value = serde_yaml::from_str(&contents).unwrap();
        for vector in data["vector"].as_sequence().unwrap() {
            let vector = vector.as_mapping().unwrap();
            let kind = vector["format"]["kind"].as_str().unwrap();
            if kind == "ssk" {
                let key = vector["format"]["params"]["key"].as_str().unwrap();
                let format = vector["format"]["params"]["format"].as_str().unwrap();
                let format = match format {
                    "sdmf" => "SSK",
                    "mdmf" => "MDMF",
                    _ => panic!("Unknown format: {:?}", format),
                };
                let result = super::derive_lafs_mutable(key, format);
                let expected = vector["expected"].as_str().unwrap();
                assert_eq!(result, expected);
            }
        }
    }
}
