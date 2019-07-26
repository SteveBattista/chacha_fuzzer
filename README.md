[![Safety Dance](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/) <br>
 Uses honggfuzz to test CHACHA20_POLY1305.<BR>
 Content to encrypt/decrypt comes from random value provided by honggfuzz <br>
 Key to derive the sealing_key and the opening_key is a SHA256 hash of the content. <br>
 The nonce is the first 12 bytes of a SHA256 hash of the key.<br>
 Program should crash if the decrypted_data does not match the original content.
