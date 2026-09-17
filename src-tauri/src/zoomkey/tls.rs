//! ZoomKey 的 mTLS 客户端配置。
//!
//! 实测：`jira.zoomkey.com.cn` 与 `crm.zoomkey.com.cn` 都强制要求客户端证书，
//! 不带证书握手直接失败（`ERR_SSL_TLSV13_ALERT_CERTIFICATE_REQUIRED`）。
//! 同时服务端证书由公司自建 Root CA 签发，必须带上 CA bundle 才能验通。
//!
//! 客户端证书与私钥来自金库的 `ClientCert` 条目（内存中），
//! CA bundle 是公开的证书链，走文件路径即可。

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, RootCertStore};
use std::collections::HashMap;
use std::io::Cursor;
use std::sync::{Arc, Mutex, OnceLock};

const CACHE_CAP: usize = 8;

pub fn build_client_config(
    ca_pem: &str,
    cert_pem: &str,
    key_pem: &str,
) -> Result<Arc<ClientConfig>, String> {
    let mut roots = RootCertStore::empty();
    let mut ca_cursor = Cursor::new(ca_pem.as_bytes());
    let mut ca_added = 0usize;
    for cert in rustls_pemfile::certs(&mut ca_cursor) {
        let cert = cert.map_err(|e| format!("CA bundle 解析失败: {e}"))?;
        roots
            .add(cert)
            .map_err(|e| format!("CA bundle 中有不受支持的证书: {e}"))?;
        ca_added += 1;
    }
    if ca_added == 0 {
        return Err("CA bundle 里没有可用的证书，请确认指向的是 PEM 格式的证书链".into());
    }

    let mut cert_cursor = Cursor::new(cert_pem.as_bytes());
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_cursor)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("客户端证书解析失败: {e}"))?;
    if certs.is_empty() {
        return Err("客户端证书里没有可用的证书".into());
    }

    let mut key_cursor = Cursor::new(key_pem.as_bytes());
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_cursor)
        .map_err(|e| format!("客户端私钥解析失败: {e}"))?
        .ok_or_else(|| "客户端私钥里没有可用的私钥".to_string())?;

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("TLS 初始化失败: {e}"))?
        .with_root_certificates(roots)
        .with_client_auth_cert(certs, key)
        .map_err(|e| format!("客户端证书与私钥不匹配: {e}"))?;
    Ok(Arc::new(config))
}

fn cache() -> &'static Mutex<HashMap<String, Arc<ClientConfig>>> {
    static CACHE: OnceLock<Mutex<HashMap<String, Arc<ClientConfig>>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// 按证书内容哈希缓存，避免每次请求都重新解析 PEM 与重建根证书库。
pub fn clear_cache() {
    if let Ok(mut guard) = cache().lock() {
        guard.clear();
    }
}

pub fn cached_client_config(
    ca_pem: &str,
    cert_pem: &str,
    key_pem: &str,
) -> Result<Arc<ClientConfig>, String> {
    let fingerprint =
        crate::http_guard::sha256_hex(format!("{ca_pem}\u{1}{cert_pem}\u{1}{key_pem}").as_bytes());
    if let Ok(guard) = cache().lock() {
        if let Some(config) = guard.get(&fingerprint) {
            return Ok(config.clone());
        }
    }
    let config = build_client_config(ca_pem, cert_pem, key_pem)?;
    if let Ok(mut guard) = cache().lock() {
        if guard.len() >= CACHE_CAP {
            guard.clear();
        }
        guard.insert(fingerprint, config.clone());
    }
    Ok(config)
}

/// 私钥若带口令，rustls-pemfile 无法解密，这里给出可执行的提示。
pub fn describe_key_error(raw: &str) -> String {
    if raw.contains("ENCRYPTED PRIVATE KEY") {
        return "客户端私钥是加密的。请先解密再存进金库，例如：\
                openssl pkcs8 -topk8 -nocrypt -in client-key.pem -out client-key-plain.pem"
            .to_string();
    }
    raw.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    const CA: &str = "-----BEGIN CERTIFICATE-----\nnot-a-real-cert\n-----END CERTIFICATE-----\n";

    #[test]
    fn rejects_empty_ca_bundle() {
        let err = build_client_config("", "", "").unwrap_err();
        assert!(err.contains("CA bundle"), "{err}");
    }

    #[test]
    fn rejects_broken_ca_bundle() {
        let err = build_client_config(CA, "", "").unwrap_err();
        assert!(err.contains("CA bundle"), "{err}");
    }

    #[test]
    fn explains_encrypted_key() {
        let msg = describe_key_error("unsupported: ENCRYPTED PRIVATE KEY");
        assert!(msg.contains("openssl"), "{msg}");
        assert_eq!(describe_key_error("other"), "other");
    }
}
