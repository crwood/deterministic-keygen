Degen - a deterministic key-generator
=====================================

_Degen_ is an experimental Rust and Python library for generating cryptographic keys deterministically, i.e., repeatably deriving the same key-material (output) given the same initial bytes of entropy (input). This can be used by applications to regenerate or restore a given key from some user-supplied input (for example, a BIP-39 mnemonic phrase), potentially enabling more "human-friendly" forms of key backup and recovery.

Currently, only RSA keys are supported.


> [!WARNING]
> This library is an early proof-of-concept that has not been audited and is subject to change; do not use this for anything important!
