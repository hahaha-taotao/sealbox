use base64::Engine;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::io::{Cursor, Read};
use std::path::Path;
use thiserror::Error;

pub const MAX_CERT_PEM_BYTES: usize = 512 * 1024;
pub const MAX_KEY_PEM_BYTES: usize = 512 * 1024;
pub const MAX_PASSPHRASE_BYTES: usize = 4096;
pub const MAX_TOTAL_PEM_BYTES: usize = 1024 * 1024;

#[derive(Debug, Error)]
pub enum CertificateError {
    #[error("{label}不能为空")]
    Empty { label: &'static str },
    #[error("{label}超过大小上限（最多 {max} 字节）")]
    TooLarge { label: &'static str, max: usize },
    #[error("{label}不是有效的 UTF-8 文本")]
    InvalidUtf8 { label: &'static str },
    #[error("客户端证书 PEM 解析失败: {0}")]
    CertificatePem(String),
    #[error("客户端证书中没有可用的 CERTIFICATE 块")]
    NoCertificate,
    #[error("客户端私钥 PEM 解析失败: {0}")]
    PrivateKeyPem(String),
    #[error("客户端私钥中没有可用的私钥；暂不支持加密私钥，请先解密后再导入")]
    NoPrivateKey,
    #[error("客户端证书与私钥不匹配，或私钥类型不受支持")]
    KeyMismatch,
    #[error("读取{label}失败: {source}")]
    Io {
        label: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[error("{label}路径不是文件")]
    NotAFile { label: &'static str },
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ClientCertMetadata {
    pub fingerprint: String,
    pub certificate_count: usize,
}

pub fn normalize_pem(
    raw: &str,
    label: &'static str,
    max_bytes: usize,
) -> Result<String, CertificateError> {
    let normalized = raw.replace("\r\n", "\n").replace('\r', "\n");
    let trimmed = normalized.trim();
    if trimmed.is_empty() {
        return Err(CertificateError::Empty { label });
    }
    if trimmed.len() > max_bytes {
        return Err(CertificateError::TooLarge {
            label,
            max: max_bytes,
        });
    }
    let mut output = trimmed.to_string();
    output.push('\n');
    Ok(output)
}

pub fn validate_client_cert(
    cert_pem: &str,
    key_pem: &str,
    passphrase: Option<&str>,
) -> Result<ClientCertMetadata, CertificateError> {
    prepare_client_cert(cert_pem, key_pem, passphrase).map(|(_, _, _, metadata)| metadata)
}

pub fn prepare_client_cert(
    cert_pem: &str,
    key_pem: &str,
    passphrase: Option<&str>,
) -> Result<(String, String, Option<String>, ClientCertMetadata), CertificateError> {
    let cert_pem = normalize_pem(cert_pem, "客户端证书", MAX_CERT_PEM_BYTES)?;
    let key_pem = normalize_pem(key_pem, "客户端私钥", MAX_KEY_PEM_BYTES)?;
    if cert_pem.len().saturating_add(key_pem.len()) > MAX_TOTAL_PEM_BYTES {
        return Err(CertificateError::TooLarge {
            label: "客户端证书和私钥总内容",
            max: MAX_TOTAL_PEM_BYTES,
        });
    }
    let passphrase = passphrase
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    if let Some(passphrase) = passphrase.as_deref() {
        if passphrase.len() > MAX_PASSPHRASE_BYTES {
            return Err(CertificateError::TooLarge {
                label: "私钥口令",
                max: MAX_PASSPHRASE_BYTES,
            });
        }
    }

    let mut cert_reader = Cursor::new(cert_pem.as_bytes());
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| CertificateError::CertificatePem(e.to_string()))?;
    let first_der = certs
        .first()
        .ok_or(CertificateError::NoCertificate)?
        .as_ref()
        .to_vec();
    let certificate_count = certs.len();

    let mut key_reader = Cursor::new(key_pem.as_bytes());
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|e| CertificateError::PrivateKeyPem(e.to_string()))?
        .ok_or(CertificateError::NoPrivateKey)?;

    let provider = rustls::crypto::ring::default_provider();
    rustls::sign::CertifiedKey::from_der(certs, key, &provider)
        .map_err(|_| CertificateError::KeyMismatch)?;

    let mut hasher = Sha256::new();
    hasher.update(first_der);
    let digest = hasher.finalize();
    let metadata = ClientCertMetadata {
        fingerprint: format!(
            "SHA256:{}",
            base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest)
        ),
        certificate_count,
    };
    Ok((cert_pem, key_pem, passphrase, metadata))
}

pub fn read_text_file(
    path: &str,
    label: &'static str,
    max_bytes: usize,
) -> Result<String, CertificateError> {
    let path_ref = Path::new(path.trim());
    if !path_ref.is_file() {
        return Err(CertificateError::NotAFile { label });
    }
    let mut file =
        std::fs::File::open(path_ref).map_err(|source| CertificateError::Io { label, source })?;
    let mut bytes = Vec::new();
    let read_limit = max_bytes.saturating_add(1);
    let mut limited = (&mut file).take(read_limit as u64);
    limited
        .read_to_end(&mut bytes)
        .map_err(|source| CertificateError::Io { label, source })?;
    if bytes.len() > max_bytes {
        return Err(CertificateError::TooLarge {
            label,
            max: max_bytes,
        });
    }
    String::from_utf8(bytes).map_err(|_| CertificateError::InvalidUtf8 { label })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_line_endings_and_adds_terminal_newline() {
        assert_eq!(normalize_pem("  a\r\nb  ", "测试", 10).unwrap(), "a\nb\n");
    }

    #[test]
    fn rejects_empty_and_oversized_input() {
        assert!(matches!(
            normalize_pem("  ", "证书", 10),
            Err(CertificateError::Empty { .. })
        ));
        assert!(matches!(
            normalize_pem("12345", "证书", 4),
            Err(CertificateError::TooLarge { .. })
        ));
    }

    #[test]
    fn rejects_malformed_pem_without_leaking_contents() {
        let err = validate_client_cert("not a cert", "not a key", None).unwrap_err();
        let text = err.to_string();
        assert!(!text.contains("not a cert"));
        assert!(!text.contains("not a key"));
    }
}
