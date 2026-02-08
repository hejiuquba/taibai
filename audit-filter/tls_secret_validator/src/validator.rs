use base64::prelude::*;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer,
};

// 在模块层面初始化密码学提供者
mod crypto_init {
    use super::*;
    use std::sync::Once;

    static INIT: Once = Once::new();

    pub fn ensure_initialized() {
        INIT.call_once(|| {
            // 明确使用 ring 提供者
            let provider = rustls::crypto::ring::default_provider();
            CryptoProvider::install_default(provider)
                .expect("Failed to install ring crypto provider");
        });
    }
}

#[derive(Debug)]
pub enum ValidationError {
    CertificateParse(String),
    PrivateKeyParse(String),
    KeyMismatch,
    TlsError(String),
}

// 为 ValidationError 实现 Display trait 来替代 thiserror 的 #[error]
impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationError::CertificateParse(msg) => {
                write!(f, "certificate parse error: {}", msg)
            }
            ValidationError::PrivateKeyParse(msg) => {
                write!(f, "private key parse error: {}", msg)
            }
            ValidationError::KeyMismatch => {
                write!(f, "tls: private key does not match public key")
            }
            ValidationError::TlsError(msg) => {
                write!(f, "tls: {}", msg)
            }
        }
    }
}

// 实现 Error trait 以保持与原始错误类型的兼容性
impl std::error::Error for ValidationError {}

/// 精确模拟Go的tls.X509KeyPair函数的行为
pub fn x509_key_pair_rust(cert_data: &[u8], key_data: &[u8]) -> Result<(), ValidationError> {
    // 确保密码学提供者已初始化
    crypto_init::ensure_initialized();

    // 1. 解析证书链
    let certs = parse_certificates(cert_data)
        .map_err(ValidationError::CertificateParse)?;

    let first_cert = certs
        .first()
        .ok_or_else(|| {
            ValidationError::TlsError(
                "failed to find any PEM data in certificate input".to_string(),
            )
        })?
        .clone(); // 克隆证书数据

    // 2. 解析私钥
    let private_key = parse_private_key(key_data)
        .map_err(ValidationError::PrivateKeyParse)?;

    // 3. 尝试构建ServerConfig来验证匹配性
    match try_build_server_config(vec![first_cert], private_key) {
        Ok(_) => Ok(()),
        Err(_) => Err(ValidationError::KeyMismatch),
    }
}

/// 通过尝试构建ServerConfig来验证证书和密钥的匹配性
fn try_build_server_config(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<(), String> {
    match rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
    {
        Ok(_) => Ok(()),
        Err(e) => {
            // 分析错误类型，转换为适当的错误信息
            let err_str = e.to_string();
            if err_str.contains("invalid peer certificate")
                || err_str.contains("private key")
                || err_str.contains("certificate")
                || err_str.contains("key")
            {
                Err("key mismatch".to_string())
            } else {
                Err(err_str)
            }
        }
    }
}

/// 解析证书数据，支持PEM和DER格式
fn parse_certificates(data: &[u8]) -> Result<Vec<CertificateDer<'static>>, String> {
    if data.is_empty() {
        return Err("empty certificate data".to_string());
    }

    let data_str = String::from_utf8_lossy(data);

    // 检查是否是PEM格式
    if data_str.contains("-----BEGIN CERTIFICATE-----") {
        parse_pem_certificates(&data_str)
    } else {
        // 作为DER格式处理
        Ok(vec![CertificateDer::from(data.to_vec())])
    }
}

/// 解析PEM格式的证书
fn parse_pem_certificates(pem_str: &str) -> Result<Vec<CertificateDer<'static>>, String> {
    let mut certs = Vec::new();
    let mut current_section = String::new();
    let mut in_cert_section = false;

    for line in pem_str.lines() {
        let line = line.trim();

        if line == "-----BEGIN CERTIFICATE-----" {
            if in_cert_section {
                return Err("nested certificate block".to_string());
            }
            in_cert_section = true;
            current_section.clear();
        } else if line == "-----END CERTIFICATE-----" {
            if !in_cert_section {
                return Err("unexpected END CERTIFICATE".to_string());
            }
            in_cert_section = false;

            // 解码Base64证书数据
            let der = BASE64_STANDARD
                .decode(&current_section)
                .map_err(|e| format!("certificate base64 decode failed: {}", e))?;

            certs.push(CertificateDer::from(der));
            current_section.clear();
        } else if in_cert_section && !line.is_empty() {
            // 收集证书的Base64数据
            current_section.push_str(line);
        }
    }

    if in_cert_section {
        return Err("unterminated certificate block".to_string());
    }

    if certs.is_empty() {
        Err("no certificate found".to_string())
    } else {
        Ok(certs)
    }
}

/// 解析私钥数据，支持多种格式
fn parse_private_key(data: &[u8]) -> Result<PrivateKeyDer<'static>, String> {
    if data.is_empty() {
        return Err("empty private key data".to_string());
    }

    let data_str = String::from_utf8_lossy(data);

    // 检查是否是PEM格式
    if data_str.contains("-----BEGIN ") && data_str.contains("PRIVATE KEY-----") {
        parse_pem_private_key(&data_str)
    } else {
        // 作为DER格式处理（假设为PKCS#8）
        Ok(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            data.to_vec(),
        )))
    }
}

/// 解析PEM格式的私钥
fn parse_pem_private_key(pem_str: &str) -> Result<PrivateKeyDer<'static>, String> {
    let lines = pem_str.lines();
    let mut in_key_section = false;
    let mut key_type = String::new();
    let mut base64_data = String::new();

    for line in lines {
        let line = line.trim();

        // 检测私钥开始标记
        if line.starts_with("-----BEGIN ") && line.contains("PRIVATE KEY-----") {
            if in_key_section {
                return Err("nested private key block".to_string());
            }
            in_key_section = true;

            // 提取密钥类型
            key_type = line
                .trim_start_matches("-----BEGIN ")
                .trim_end_matches("-----")
                .to_string();

            base64_data.clear();
        } else if line.starts_with("-----END ") && line.contains("PRIVATE KEY-----") {
            if !in_key_section {
                return Err("unexpected END private key".to_string());
            }

            // 检查结束标记是否匹配开始标记的类型
            let end_type = line
                .trim_start_matches("-----END ")
                .trim_end_matches("-----");

            if end_type != key_type {
                return Err(format!(
                    "mismatched key type: begin={}, end={}",
                    key_type, end_type
                ));
            }

            // 解码Base64并创建对应的PrivateKeyDer
            let der = BASE64_STANDARD
                .decode(&base64_data)
                .map_err(|e| format!("private key base64 decode failed: {}", e))?;

            return create_private_key_from_der(&der, &key_type);
        } else if in_key_section && !line.is_empty() {
            base64_data.push_str(line);
        }
    }

    if in_key_section {
        return Err("unterminated private key block".to_string());
    }

    Err("no valid private key found".to_string())
}

/// 根据PEM头部类型创建对应的PrivateKeyDer
fn create_private_key_from_der(
    der: &[u8],
    key_type: &str,
) -> Result<PrivateKeyDer<'static>, String> {
    match key_type {
        "PRIVATE KEY" => Ok(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der.to_vec()))),
        "RSA PRIVATE KEY" => Ok(PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(der.to_vec()))),
        "EC PRIVATE KEY" => Ok(PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(der.to_vec()))),
        "ENCRYPTED PRIVATE KEY" => Err("encrypted private keys are not supported".to_string()),
        _ => Err(format!("unsupported private key type: {}", key_type)),
    }
}

/// 模拟Kubernetes的warningsForSecret函数
pub fn warnings_for_secret_rust(
    secret_type: &str,
    tls_cert_data: Option<&[u8]>,
    tls_key_data: Option<&[u8]>,
) -> Vec<String> {
    let mut warnings = Vec::new();

    // 仅对TLS类型的Secret进行检查
    if secret_type != "kubernetes.io/tls" {
        return warnings;
    }

    match (tls_cert_data, tls_key_data) {
        (Some(cert_data), Some(key_data)) => {
            match x509_key_pair_rust(cert_data, key_data) {
                Ok(_) => (), // 无警告
                Err(e) => warnings.push(e.to_string()),
            }
        }
        _ => {
            // 缺失字段的警告
            if tls_cert_data.is_none() {
                warnings.push("Missing 'tls.crt' in secret data".to_string());
            }
            if tls_key_data.is_none() {
                warnings.push("Missing 'tls.key' in secret data".to_string());
            }
        }
    }

    warnings
}

/// 便捷函数：直接从数据Map中生成警告
pub fn warnings_for_secret_from_map(
    secret_type: &str,
    data: &std::collections::HashMap<String, Vec<u8>>,
) -> Vec<String> {
    warnings_for_secret_rust(
        secret_type,
        data.get("tls.crt").map(|v| v.as_slice()),
        data.get("tls.key").map(|v| v.as_slice()),
    )
}