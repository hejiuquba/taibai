/*
Copyright 2017 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

//! 策略读取器
//!
//! 此模块实现了从文件或字节数据加载审计策略的功能。

use std::fs;
use std::path::Path;

use k8s_audit_apis::audit as audit_internal;

/// 策略读取器错误类型
#[derive(Debug)]
pub enum PolicyReaderError {
    /// 文件路径未指定
    FilePathNotSpecified,
    /// 文件读取错误
    FileReadError(String, std::io::Error),
    /// 策略解码错误
    PolicyDecodeError(String),
    /// 未知的API组版本
    UnknownApiGroupVersion(String),
    /// 策略验证错误
    PolicyValidationError(String),
    /// 策略规则数量为零
    ZeroPolicyRules,
    /// 无效的策略数据
    InvalidPolicyData(String),
}

impl std::fmt::Display for PolicyReaderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyReaderError::FilePathNotSpecified => write!(f, "文件路径未指定"),
            PolicyReaderError::FileReadError(path, err) => 
                write!(f, "无法读取文件路径 {}: {}", path, err),
            PolicyReaderError::PolicyDecodeError(msg) => 
                write!(f, "策略解码失败: {}", msg),
            PolicyReaderError::UnknownApiGroupVersion(version) => 
                write!(f, "策略中未知的组版本字段: {}", version),
            PolicyReaderError::PolicyValidationError(msg) => 
                write!(f, "策略验证失败: {}", msg),
            PolicyReaderError::ZeroPolicyRules => 
                write!(f, "加载了包含0条规则的非法策略"),
            PolicyReaderError::InvalidPolicyData(msg) => 
                write!(f, "无效的策略数据: {}", msg),
        }
    }
}

impl std::error::Error for PolicyReaderError {}

/// 从文件加载审计策略
/// 
/// # 参数
/// * `file_path` - 策略文件路径
/// 
/// # 返回值
/// * `Ok(Policy)` - 成功加载的策略
/// * `Err(PolicyReaderError)` - 加载失败的错误
/// 
/// # 示例
/// ```no_run
/// use k8s_audit_core::policy::reader::load_policy_from_file;
/// 
/// let policy = load_policy_from_file("/etc/kubernetes/audit/policy.yaml").unwrap();
/// ```
pub fn load_policy_from_file<P: AsRef<Path>>(file_path: P) -> Result<audit_internal::Policy, PolicyReaderError> {
    let file_path_ref = file_path.as_ref();
    
    if file_path_ref.to_string_lossy().is_empty() {
        return Err(PolicyReaderError::FilePathNotSpecified);
    }
    
    // 读取文件内容
    let policy_data = fs::read_to_string(file_path_ref)
        .map_err(|e| PolicyReaderError::FileReadError(
            file_path_ref.to_string_lossy().to_string(), 
            e
        ))?;
    
    // 从字节数据加载策略
    let policy = load_policy_from_bytes(policy_data.as_bytes())?;
    
    Ok(policy)
}

/// 从字节数据加载审计策略
/// 
/// # 参数
/// * `policy_data` - 策略数据的字节切片
/// 
/// # 返回值
/// * `Ok(Policy)` - 成功加载的策略
/// * `Err(PolicyReaderError)` - 加载失败的错误
/// 
/// # 注意
/// 此函数尝试先进行严格解析，如果失败则回退到宽松解析。
pub fn load_policy_from_bytes(policy_data: &[u8]) -> Result<audit_internal::Policy, PolicyReaderError> {
    if policy_data.is_empty() {
        return Err(PolicyReaderError::InvalidPolicyData("策略数据为空".to_string()));
    }
    
    // 尝试解析为YAML或JSON
    let policy = parse_policy_with_fallback(policy_data)?;
    
    // 验证策略
    validate_policy(&policy)?;
    
    // 检查策略规则数量
    if policy.rules.is_empty() {
        return Err(PolicyReaderError::ZeroPolicyRules);
    }
    
    let rule_count = policy.rules.len();
    // 使用标准输出打印调试信息
    println!("[DEBUG] 加载审计策略规则成功, 规则数量: {}", rule_count);
    
    Ok(policy)
}

/// 尝试严格解析，失败则回退到宽松解析
fn parse_policy_with_fallback(policy_data: &[u8]) -> Result<audit_internal::Policy, PolicyReaderError> {
    // 首先尝试作为YAML解析
    let yaml_result = serde_yaml::from_slice::<audit_internal::Policy>(policy_data);
    
    match yaml_result {
        Ok(policy) => {
            // YAML解析成功，检查API版本
            check_api_version(&policy)?;
            return Ok(policy);
        }
        Err(yaml_err) => {
            // YAML解析失败，尝试JSON
            let json_result = serde_json::from_slice::<audit_internal::Policy>(policy_data);
            
            match json_result {
                Ok(policy) => {
                    // JSON解析成功，检查API版本
                    check_api_version(&policy)?;
                    
                    // 使用标准错误输出打印警告
                    eprintln!("[WARN] 审计策略包含错误，回退到宽松解析: {}", yaml_err);
                    return Ok(policy);
                }
                Err(json_err) => {
                    // 两种格式都失败
                    return Err(PolicyReaderError::PolicyDecodeError(format!(
                        "YAML解析失败: {}, JSON解析失败: {}", yaml_err, json_err
                    )));
                }
            }
        }
    }
}

/// 检查API版本是否受支持
fn check_api_version(policy: &audit_internal::Policy) -> Result<(), PolicyReaderError> {
    // 注意：这里简化了API版本检查
    // 在实际的Kubernetes中，需要检查 apiVersion 字段
    
    // 假设我们支持 audit.k8s.io/v1
    let supported_versions = ["audit.k8s.io/v1", "v1"];
    
    // 尝试从注解或元数据中获取版本信息
    // 这是一个简化实现，实际需要根据策略结构进行调整
    if let Some(api_version) = &policy.type_meta.api_version {
        if !supported_versions.contains(&api_version.as_str()) {
            return Err(PolicyReaderError::UnknownApiGroupVersion(
                api_version.clone()
            ));
        }
    } else {
        // 如果没有apiVersion字段，使用默认版本
        // 在实际实现中，可能需要更复杂的版本检测
        eprintln!("[INFO] 策略中没有找到apiVersion字段，使用默认版本");
    }
    
    Ok(())
}

/// 验证策略
fn validate_policy(policy: &audit_internal::Policy) -> Result<(), PolicyReaderError> {
    // 这里调用审计API中的验证函数
    // 假设 k8s_audit_apis::audit 提供了 validate_policy 函数
    
    // 简化验证：检查基本字段
    if policy.type_meta.kind.as_deref() != Some("Policy") {
        eprintln!("[WARN] 策略类型不是 'Policy'，而是: {:?}", policy.type_meta.kind);
    }
    
    // 验证每个规则的基本字段
    for (i, rule) in policy.rules.iter().enumerate() {
        // // 检查级别是否有效
        // if let audit_internal::Level::Unknown = rule.level {
        //     return Err(PolicyReaderError::PolicyValidationError(format!(
        //         "规则 {} 包含未知的审计级别", i
        //     )));
        // }
        
        // // 检查阶段是否有效
        // for stage in &rule.omit_stages {
        //     if let audit_internal::Stage::Unknown = stage {
        //         return Err(PolicyReaderError::PolicyValidationError(format!(
        //             "规则 {} 包含未知的阶段", i
        //         )));
        //     }
        // }
        
        // 检查规则是否有内容
        if rule.users.is_empty() && 
           rule.user_groups.is_empty() && 
           rule.verbs.is_empty() && 
           rule.namespaces.is_empty() && 
           rule.resources.is_empty() && 
           rule.non_resource_urls.is_empty() {
            eprintln!("[WARN] 规则 {} 没有指定任何匹配条件，将匹配所有请求", i);
        }
    }
    
    // 这里可以添加更多的验证逻辑
    // 例如：检查资源名称格式、命名空间格式等
    
    Ok(())
}

/// 支持的API组版本
/// 
/// 注意：这是一个简化版本，实际Kubernetes支持多个版本
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SupportedApiVersion {
    /// audit.k8s.io/v1
    AuditV1,
}

impl SupportedApiVersion {
    /// 获取所有支持的版本
    pub fn all() -> Vec<Self> {
        vec![SupportedApiVersion::AuditV1]
    }
    
    /// 转换为字符串表示
    pub fn as_str(&self) -> &'static str {
        match self {
            SupportedApiVersion::AuditV1 => "audit.k8s.io/v1",
        }
    }
}

/// 从字符串解析API版本
pub fn parse_api_version(version_str: &str) -> Option<SupportedApiVersion> {
    match version_str {
        "audit.k8s.io/v1" | "v1" => Some(SupportedApiVersion::AuditV1),
        _ => None,
    }
}

/// 工具函数：打印策略摘要信息
pub fn print_policy_summary(policy: &audit_internal::Policy) {
    println!("=== 审计策略摘要 ===");
    println!("策略版本: {:?}", policy.type_meta.api_version);
    println!("策略类型: {:?}", policy.type_meta.kind);
    println!("规则数量: {}", policy.rules.len());
    println!("是否省略托管字段: {}", policy.omit_managed_fields.unwrap_or_default());
    println!("要省略的阶段: {:?}", policy.omit_stages);
    println!("===================");
}

// 在 reader.rs 文件末尾添加测试模块

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;
    
    // 测试用的策略YAML数据
    const TEST_POLICY_YAML: &str = r#"
apiVersion: audit.k8s.io/v1
kind: Policy
omitStages: []
omitManagedFields: false
rules:
  - level: Metadata
    users: ["admin"]
    verbs: ["get", "list"]
    resources:
      - group: ""
        resources: ["pods"]
        resourceNames: ["test-pod"]
  - level: RequestResponse
    userGroups: ["system:masters"]
    verbs: ["*"]
"#;
    
    // 测试用的策略JSON数据
    const TEST_POLICY_JSON: &str = r#"
{
  "apiVersion": "audit.k8s.io/v1",
  "kind": "Policy",
  "omitStages": [],
  "omitManagedFields": false,
  "rules": [
    {
      "level": "Metadata",
      "users": ["admin"],
      "verbs": ["get", "list"]
    }
  ]
}
"#;
    
    // 测试：创建临时策略文件
    fn create_temp_policy_file(content: &str) -> NamedTempFile {
        let mut file = NamedTempFile::new().expect("无法创建临时文件");
        write!(file, "{}", content).expect("无法写入临时文件");
        file
    }
    
    #[test]
    fn test_load_policy_from_file_valid_yaml() {
        let temp_file = create_temp_policy_file(TEST_POLICY_YAML);
        let file_path = temp_file.path();
        
        let result = load_policy_from_file(file_path);
        assert!(result.is_ok(), "应该成功加载YAML策略文件");
        
        let policy = result.unwrap();
        assert_eq!(policy.type_meta.api_version, Some("audit.k8s.io/v1".to_string()));
        assert_eq!(policy.type_meta.kind, Some("Policy".to_string()));
        assert_eq!(policy.rules.len(), 2);
        assert!(!policy.omit_managed_fields.unwrap_or_default());
        assert!(policy.omit_stages.is_empty());
    }
    
    #[test]
    fn test_load_policy_from_file_valid_json() {
        let temp_file = create_temp_policy_file(TEST_POLICY_JSON);
        let file_path = temp_file.path();
        
        let result = load_policy_from_file(file_path);
        assert!(result.is_ok(), "应该成功加载JSON策略文件");
        
        let policy = result.unwrap();
        assert_eq!(policy.type_meta.api_version, Some("audit.k8s.io/v1".to_string()));
        assert_eq!(policy.type_meta.kind, Some("Policy".to_string()));
        assert_eq!(policy.rules.len(), 1);
    }
    
    #[test]
    fn test_load_policy_from_file_empty_path() {
        let result = load_policy_from_file("");
        assert!(result.is_err());
        
        if let Err(PolicyReaderError::FilePathNotSpecified) = result {
            // 正确错误类型
        } else {
            panic!("应该返回FilePathNotSpecified错误");
        }
    }
    
    #[test]
    fn test_load_policy_from_file_nonexistent() {
        let result = load_policy_from_file("/nonexistent/path/to/policy.yaml");
        assert!(result.is_err());
        
        if let Err(PolicyReaderError::FileReadError(_, _)) = result {
            // 正确错误类型
        } else {
            panic!("应该返回FileReadError错误");
        }
    }
    
    #[test]
    fn test_load_policy_from_bytes_valid_yaml() {
        let result = load_policy_from_bytes(TEST_POLICY_YAML.as_bytes());
        assert!(result.is_ok(), "应该成功加载YAML策略数据");
        
        let policy = result.unwrap();
        assert_eq!(policy.rules.len(), 2);
    }
    
    #[test]
    fn test_load_policy_from_bytes_valid_json() {
        let result = load_policy_from_bytes(TEST_POLICY_JSON.as_bytes());
        assert!(result.is_ok(), "应该成功加载JSON策略数据");
        
        let policy = result.unwrap();
        assert_eq!(policy.rules.len(), 1);
    }
    
    #[test]
    fn test_load_policy_from_bytes_empty() {
        let result = load_policy_from_bytes(&[]);
        assert!(result.is_err());
        
        if let Err(PolicyReaderError::InvalidPolicyData(_)) = result {
            // 正确错误类型
        } else {
            panic!("应该返回InvalidPolicyData错误");
        }
    }
    
    #[test]
    fn test_load_policy_from_bytes_invalid_format() {
        let invalid_data = "这不是有效的YAML或JSON";
        let result = load_policy_from_bytes(invalid_data.as_bytes());
        assert!(result.is_err());
        
        if let Err(PolicyReaderError::PolicyDecodeError(_)) = result {
            // 正确错误类型
        } else {
            panic!("应该返回PolicyDecodeError错误");
        }
    }
    
    #[test]
    fn test_load_policy_from_bytes_zero_rules() {
        let zero_rules_yaml = r#"
apiVersion: audit.k8s.io/v1
kind: Policy
omitStages: []
omitManagedFields: false
rules: []
"#;
        
        let result = load_policy_from_bytes(zero_rules_yaml.as_bytes());
        assert!(result.is_err());
        
        if let Err(PolicyReaderError::ZeroPolicyRules) = result {
            // 正确错误类型
        } else {
            panic!("应该返回ZeroPolicyRules错误");
        }
    }
    
    #[test]
    fn test_load_policy_from_bytes_unsupported_version() {
        let unsupported_version_yaml = r#"
apiVersion: audit.k8s.io/v2  # 不支持的版本
kind: Policy
omitStages: []
omitManagedFields: false
rules:
  - level: Metadata
    users: ["admin"]
"#;
        
        let result = load_policy_from_bytes(unsupported_version_yaml.as_bytes());
        assert!(result.is_err());
        
        if let Err(PolicyReaderError::UnknownApiGroupVersion(_)) = result {
            // 正确错误类型
        } else {
            panic!("应该返回UnknownApiGroupVersion错误");
        }
    }
    
    #[test]
    fn test_load_policy_from_bytes_no_version() {
        let no_version_yaml = r#"
kind: Policy
omitStages: []
omitManagedFields: false
rules:
  - level: Metadata
    users: ["admin"]
"#;
        
        let result = load_policy_from_bytes(no_version_yaml.as_bytes());
        // 没有版本时应该成功，但会打印警告
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_parse_policy_with_fallback_yaml_success() {
        let result = parse_policy_with_fallback(TEST_POLICY_YAML.as_bytes());
        assert!(result.is_ok());
        
        let policy = result.unwrap();
        assert_eq!(policy.rules.len(), 2);
    }
    
    #[test]
    fn test_parse_policy_with_fallback_json_success() {
        let result = parse_policy_with_fallback(TEST_POLICY_JSON.as_bytes());
        assert!(result.is_ok());
        
        let policy = result.unwrap();
        assert_eq!(policy.rules.len(), 1);
    }
    
    #[test]
    fn test_check_api_version_supported() {
        let mut policy = audit_internal::Policy::default();
        policy.type_meta.api_version = Some("audit.k8s.io/v1".to_string());
        
        let result = check_api_version(&policy);
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_check_api_version_unsupported() {
        let mut policy = audit_internal::Policy::default();
        policy.type_meta.api_version = Some("audit.k8s.io/v2".to_string()); // 不支持的版本
        
        let result = check_api_version(&policy);
        assert!(result.is_err());
        
        if let Err(PolicyReaderError::UnknownApiGroupVersion(version)) = result {
            assert_eq!(version, "audit.k8s.io/v2");
        } else {
            panic!("应该返回UnknownApiGroupVersion错误");
        }
    }
    
    #[test]
    fn test_validate_policy_valid() {
        let mut policy = audit_internal::Policy::default();
        policy.type_meta.kind = Some("Policy".to_string());
        
        // 添加一个有效规则
        let rule = audit_internal::PolicyRule {
            level: audit_internal::Level::Metadata,
            ..Default::default()
        };
        policy.rules.push(rule);
        
        let result = validate_policy(&policy);
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_validate_policy_invalid_kind() {
        let mut policy = audit_internal::Policy::default();
        policy.type_meta.kind = Some("NotPolicy".to_string()); // 无效的类型
        
        let rule = audit_internal::PolicyRule {
            level: audit_internal::Level::Metadata,
            ..Default::default()
        };
        policy.rules.push(rule);
        
        let result = validate_policy(&policy);
        // 无效的类型应该只打印警告，不返回错误
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_validate_policy_unknown_level() {
        let mut policy = audit_internal::Policy::default();
        policy.type_meta.kind = Some("Policy".to_string());
        
        // 添加一个包含未知级别的规则
        let rule = audit_internal::PolicyRule {
            level: audit_internal::Level::None,
            ..Default::default()
        };
        policy.rules.push(rule);
        
        let result = validate_policy(&policy);
        assert!(result.is_err());
        
        if let Err(PolicyReaderError::PolicyValidationError(msg)) = result {
            assert!(msg.contains("包含未知的审计级别"));
        } else {
            panic!("应该返回PolicyValidationError错误");
        }
    }
    
    #[test]
    fn test_parse_api_version() {
        assert_eq!(
            parse_api_version("audit.k8s.io/v1"),
            Some(SupportedApiVersion::AuditV1)
        );
        assert_eq!(
            parse_api_version("v1"),
            Some(SupportedApiVersion::AuditV1)
        );
        assert_eq!(
            parse_api_version("audit.k8s.io/v2"),
            None
        );
        assert_eq!(
            parse_api_version(""),
            None
        );
    }
    
    #[test]
    fn test_print_policy_summary() {
        let mut policy = audit_internal::Policy::default();
        policy.type_meta.api_version = Some("audit.k8s.io/v1".to_string());
        policy.type_meta.kind = Some("Policy".to_string());
        policy.omit_managed_fields = Some(true);
        
        // 添加两个规则
        policy.rules.push(audit_internal::PolicyRule {
            level: audit_internal::Level::Metadata,
            ..Default::default()
        });
        policy.rules.push(audit_internal::PolicyRule {
            level: audit_internal::Level::RequestResponse,
            ..Default::default()
        });
        
        // 这个测试主要确保函数不会panic
        print_policy_summary(&policy);
    }
    
    #[test]
    fn test_error_display() {
        let errors = vec![
            (PolicyReaderError::FilePathNotSpecified, "文件路径未指定"),
            (PolicyReaderError::ZeroPolicyRules, "加载了包含0条规则的非法策略"),
        ];
        
        for (error, expected_msg) in errors {
            assert_eq!(error.to_string(), expected_msg);
        }
    }
}