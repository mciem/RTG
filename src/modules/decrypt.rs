use std::panic;
use std::ptr::null_mut;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use aes_gcm::aead::Aead;
use winapi::um::dpapi::CryptUnprotectData;
use winapi::um::wincrypt::DATA_BLOB;

pub fn decrypt_value(buff: &[u8], master_key: &[u8]) -> Result<Vec<u8>, aes_gcm::Error> {
    let starts = std::str::from_utf8(&buff[..3]).expect("Bytes should be valid utf8");
    if starts == "v10" || starts == "v11" {
        let iv = &buff[3..15];
        let payload = &buff[15..];
        let key = Key::<Aes256Gcm>::from_slice(master_key);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(iv);

        cipher.decrypt(nonce, payload)
    } else {
        panic!("Unsupported version!")
    }
}

pub fn crypt_unprotect_data(data: &[u8]) -> Vec<u8> {
    unsafe {
        let mut in_blob = DATA_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr() as *mut u8,
        };
        let mut out_blob = DATA_BLOB {
            cbData: 0,
            pbData: null_mut(),
        };

        if CryptUnprotectData(
            &mut in_blob,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            0,
            &mut out_blob,
        ) == 0 {
            panic!("Failed to CryptUnprotectData")
        }

        let result = std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize).to_vec();
        winapi::um::winbase::LocalFree(out_blob.pbData as *mut _);

        result
    }
}