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
                println!("{:?}", key);
                let expected = vector["expected"].as_str().unwrap();
                let parts: Vec<&str> = expected.split(':').collect();
                let writekey = parts[2];
                let fingerprint = parts[3];
                println!("{:?} {:?} {:?}", expected, writekey, fingerprint);
            }
        }
        // assert_eq!(1, 2, "Not yet implemented");
    }
}
