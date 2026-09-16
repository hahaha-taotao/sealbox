use sealbox_lib::crypto::{
    decrypt, derive_kek, encrypt, unwrap_key, wrap_key, ArgonParams, CryptoError, ARGON_M_COST,
    ARGON_P_COST, ARGON_T_COST,
};

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

#[test]
fn import_kdf_bounds_reject_weak_and_huge_params() {
    let ok = ArgonParams {
        salt: [1u8; 16],
        m_cost: ARGON_M_COST,
        t_cost: ARGON_T_COST,
        p_cost: ARGON_P_COST,
    };
    assert!(ok.validate_import_bounds().is_ok());

    let weak = ArgonParams {
        m_cost: 1,
        ..ok.clone()
    };
    match weak.validate_import_bounds() {
        Err(CryptoError::KdfOutOfRange) => {}
        other => panic!("expected KdfOutOfRange, got {other:?}"),
    }

    let huge = ArgonParams {
        m_cost: 2_000_000,
        ..ok.clone()
    };
    match huge.validate_import_bounds() {
        Err(CryptoError::KdfOutOfRange) => {}
        other => panic!("expected KdfOutOfRange, got {other:?}"),
    }

    let cheap_time = ArgonParams {
        t_cost: 1,
        ..ok.clone()
    };
    assert!(matches!(
        cheap_time.validate_import_bounds(),
        Err(CryptoError::KdfOutOfRange)
    ));

    let many_lanes = ArgonParams { p_cost: 64, ..ok };
    assert!(matches!(
        many_lanes.validate_import_bounds(),
        Err(CryptoError::KdfOutOfRange)
    ));
}
