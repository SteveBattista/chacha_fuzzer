#![forbid(unsafe_code)]
#[macro_use]
extern crate honggfuzz;

use ring::aead::*;
use ring::digest::{Context, SHA256};

fn main() {
    // Here you can parse `std::env::args and
    // setup / initialize your project
    // You have full control over the loop but
    // you're supposed to call `fuzz` ad vitam aeternam
    loop {
        // The fuzz macro gives an arbitrary object (see `arbitrary crate`)
        // to a closure-like block of code.
        // For performance reasons, it is recommended that you use the native type
        // `&[u8]` when possible.
        // Here, this slice will contain a "random" quantity of "random" data.
        fuzz!(|data: &[u8]| {
            // Use this to create a 32 bit key from random input
            let key = &mut [0; 32];
            let mut context = Context::new(&SHA256);
            context.update(&data);
            key.copy_from_slice(&context.finish().as_ref()[..]);

            // Random data to encrypt
            let content = data.to_vec();

            // Ring uses the same input variable as output
            let mut in_out = content.clone();

            // The input/output variable need some space for a suffix
            //println!("Tag len {}", CHACHA20_POLY1305.tag_len());
            for _ in 0..CHACHA20_POLY1305.tag_len() {
                in_out.push(0);
            }

            // Opening key used to decrypt data
            let opening_key = OpeningKey::new(&CHACHA20_POLY1305, key).unwrap();

            // Sealing key used to encrypt data
            let sealing_key = SealingKey::new(&CHACHA20_POLY1305, key).unwrap();

            // Random nonce is first 12 bytes of a hash of the key
            let nonce_byte = &mut [0; 12];
            let mut context = Context::new(&SHA256);
            context.update(&key[..]);
            nonce_byte.copy_from_slice(&context.finish().as_ref()[0..12]);

            // Encrypt data into in_out variable
            seal_in_place(
                &sealing_key,
                Nonce::assume_unique_for_key(*nonce_byte),
                Aad::empty(),
                &mut in_out,
                CHACHA20_POLY1305.tag_len(),
            )
            .unwrap();

            // println!("Encrypted data's size {}", output_size);

            let decrypted_data = open_in_place(
                &opening_key,
                Nonce::assume_unique_for_key(*nonce_byte),
                Aad::empty(),
                0,
                &mut in_out,
            )
            .unwrap();

            //println!("{:?}", String::from_utf8(decrypted_data.to_vec()).unwrap());
            assert_eq!(content, decrypted_data);
        });
    }
}
