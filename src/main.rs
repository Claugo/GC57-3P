use aes::{Aes256, BlockEncrypt, BlockDecrypt, NewBlockCipher};
use aes::cipher::{BlockCipher, KeyInit, generic_array::GenericArray};
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use std::str;

const BLOCK_SIZE: usize = 16;

fn decrypt_aes256_cbc(key: &[u8; 32], iv: &[u8; 16], ciphertext: &[u8]) -> Vec<u8> {
    let cipher = Cbc::<Aes256, Pkcs7>::new_from_slices(key, iv).unwrap();
    cipher.decrypt_vec(ciphertext).expect("Decryption failed")
}

fn main() {
    let key: [u8; 32] = [0u8; 32]; // Replace with your actual key
    let iv: [u8; 16] = [0u8; 16];  // Replace with your actual IV
    let ciphertext: Vec<u8> = vec![]; // Your ciphertext here
    
    match decrypt_aes256_cbc(&key, &iv, &ciphertext) {
        Ok(plaintext) => {
            println!("Decrypted text: {:x?}", plaintext);
        }
        Err(e) => {
            eprintln!("Error decrypting: {}", e);
        }
    }
}