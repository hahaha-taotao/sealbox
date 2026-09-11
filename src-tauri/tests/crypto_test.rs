use sealbox_lib::crypto::{decrypt, derive_kek, encrypt, unwrap_key, wrap_key, ArgonParams};

#[test]
fn encrypt_decrypt_roundtrip() {
    let dek = [7u8; 32];
    let ct = encrypt(&dek, b"hello secret").unwrap();
    let pt = decrypt(&dek, &ct).unwrap();
    assert_eq!(pt, b"hello secret");
}

#[test]
fn decrypt_rejects_tamper() {
    let dek = [7u8; 32];
    let mut ct = encrypt(&dek, b"hello secret").unwrap();
    ct.ciphertext[0] ^= 0x01;
    assert!(decrypt(&dek, &ct).is_err());
}

#[test]
fn wrap_unwrap_dek() {
    let kek = [3u8; 32];
    let dek = [9u8; 32];
    let wrapped = wrap_key(&kek, &dek).unwrap();
    let out = unwrap_key(&kek, &wrapped).unwrap();
    assert_eq!(out, dek);
}

#[test]
fn derive_kek_stable() {
    let params = ArgonParams::default();
    let a = derive_kek("correct horse", &params).unwrap();
    let b = derive_kek("correct horse", &params).unwrap();
    assert_eq!(a, b);
    let c = derive_kek("wrong", &params).unwrap();
    assert_ne!(a, c);
}
