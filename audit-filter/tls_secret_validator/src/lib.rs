//! Kubernetes-style TLS Secret validator
//! 
//! This crate provides a Rust implementation that exactly matches the behavior
//! of Go's `tls.X509KeyPair` function and Kubernetes' `warningsForSecret` function.

pub mod validator;

pub use validator::{
    x509_key_pair_rust,
    warnings_for_secret_rust,
    warnings_for_secret_from_map,
    ValidationError,
};

/// 预定义常量（与Kubernetes API常量匹配）
pub mod api {
    pub const TLSCERT_KEY: &str = "tls.crt";
    pub const TLSPRIVATE_KEY_KEY: &str = "tls.key";
    pub const SECRET_TYPE_TLS: &str = "kubernetes.io/tls";
}