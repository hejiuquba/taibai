//! 审计策略评估器

use hyper::{Body, Request};

/// 策略评估器 trait
pub trait PolicyEvaluator: Send + Sync {
    /// 评估请求是否需要审计
    fn evaluate(&self, req: &Request<Body>) -> bool;
}

/// 总是审计策略
pub struct AlwaysAuditPolicy;

impl PolicyEvaluator for AlwaysAuditPolicy {
    fn evaluate(&self, _req: &Request<Body>) -> bool {
        true
    }
}

/// 基于路径的审计策略
pub struct PathBasedPolicy {
    /// 需要审计的路径前缀
    audit_paths: Vec<String>,
}

impl PathBasedPolicy {
    pub fn new(audit_paths: Vec<String>) -> Self {
        Self { audit_paths }
    }
}

impl PolicyEvaluator for PathBasedPolicy {
    fn evaluate(&self, req: &Request<Body>) -> bool {
        let path = req.uri().path();
        self.audit_paths.iter().any(|prefix| path.starts_with(prefix))
    }
}

/// 长时间运行请求检查函数类型
pub type LongRunningCheck = Box<dyn Fn(&Request<Body>) -> bool + Send + Sync>;

/// 默认的长请求检查：检查是否是 watch 或 logs 请求
pub fn default_long_running_check(req: &Request<Body>) -> bool {
    let path = req.uri().path();
    path.contains("/watch") || path.contains("/logs")
}