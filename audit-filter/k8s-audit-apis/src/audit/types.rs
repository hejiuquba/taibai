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

//! Kubernetes 审计 API 类型定义
//!
//! 此模块定义了审计系统的核心数据结构。

use k8s_openapi::api::authentication::v1 as authnv1;
use serde::{Deserialize, Serialize};

// ========== 自定义核心类型（因为 k8s-openapi 0.21.1 缺少这些类型） ==========

/// TypeMeta 描述一个对象的类型信息
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TypeMeta {
    #[serde(rename = "apiVersion", skip_serializing_if = "Option::is_none")]
    pub api_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
}

/// ListMeta 描述列表的元数据
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ListMeta {
    #[serde(rename = "resourceVersion", skip_serializing_if = "Option::is_none")]
    pub resource_version: Option<String>,
    #[serde(rename = "continue", skip_serializing_if = "Option::is_none")]
    pub continue_: Option<String>,
    #[serde(rename = "remainingItemCount", skip_serializing_if = "Option::is_none")]
    pub remaining_item_count: Option<i64>,
}

/// ObjectMeta 是所有持久化资源必须具有的元数据
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ObjectMeta {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(rename = "uid", skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
    #[serde(rename = "resourceVersion", skip_serializing_if = "Option::is_none")]
    pub resource_version: Option<String>,
    #[serde(rename = "generation", skip_serializing_if = "Option::is_none")]
    pub generation: Option<i64>,
    #[serde(rename = "creationTimestamp", skip_serializing_if = "Option::is_none")]
    pub creation_timestamp: Option<Time>,
    #[serde(rename = "deletionTimestamp", skip_serializing_if = "Option::is_none")]
    pub deletion_timestamp: Option<Time>,
    #[serde(
        rename = "deletionGracePeriodSeconds",
        skip_serializing_if = "Option::is_none"
    )]
    pub deletion_grace_period_seconds: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<std::collections::BTreeMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotations: Option<std::collections::BTreeMap<String, String>>,
    #[serde(
        rename = "ownerReferences",
        skip_serializing_if = "Vec::is_empty",
        default
    )]
    pub owner_references: Vec<OwnerReference>,
    #[serde(rename = "finalizers", skip_serializing_if = "Vec::is_empty", default)]
    pub finalizers: Vec<String>,
    #[serde(
        rename = "managedFields",
        skip_serializing_if = "Vec::is_empty",
        default
    )]
    pub managed_fields: Vec<ManagedFieldsEntry>,
}

/// OwnerReference 包含足够的信息来识别当前对象的属主
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OwnerReference {
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    pub kind: String,
    pub name: String,
    #[serde(rename = "uid")]
    pub uid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub controller: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_owner_deletion: Option<bool>,
}

/// ManagedFieldsEntry 是描述一个管理器管理的字段的条目
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ManagedFieldsEntry {
    #[serde(rename = "manager", skip_serializing_if = "Option::is_none")]
    pub manager: Option<String>,
    #[serde(rename = "operation", skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
    #[serde(rename = "apiVersion", skip_serializing_if = "Option::is_none")]
    pub api_version: Option<String>,
    #[serde(rename = "time", skip_serializing_if = "Option::is_none")]
    pub time: Option<Time>,
    #[serde(rename = "fieldsType", skip_serializing_if = "Option::is_none")]
    pub fields_type: Option<String>,
    #[serde(rename = "fieldsV1", skip_serializing_if = "Option::is_none")]
    pub fields_v1: Option<serde_json::Value>,
}

/// Status 是返回调用者错误的类型
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Status {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<StatusDetails>,
}

/// StatusDetails 是 Status 原因的详细信息
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StatusDetails {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub causes: Vec<StatusCause>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_seconds: Option<i32>,
}

/// StatusCause 提供错误的附加信息
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StatusCause {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
}

/// Time 是时间的包装类型
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Time(#[serde(with = "time_serde")] chrono::DateTime<chrono::Utc>);

impl Default for Time {
    fn default() -> Self {
        Time(chrono::Utc::now())
    }
}

impl Time {
    /// 获取当前时间
    pub fn now() -> Self {
        Time(chrono::Utc::now())
    }
    
    /// 从系统时间创建
    pub fn from_system_time(system_time: std::time::SystemTime) -> Self {
        let datetime: chrono::DateTime<chrono::Utc> = system_time.into();
        Time(datetime)
    }
    
    /// 格式化为RFC3339Nano字符串
    pub fn to_rfc3339_nano(&self) -> String {
        self.0.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true)
    }
    
    /// 获取内部的 DateTime
    pub fn as_datetime(&self) -> &chrono::DateTime<chrono::Utc> {
        &self.0
    }
}

// 为 SystemTime 到 Time 提供转换
impl From<std::time::SystemTime> for Time {
    fn from(system_time: std::time::SystemTime) -> Self {
        Self::from_system_time(system_time)
    }
}

// 为 Time 到 SystemTime 提供转换（如果需要）
impl From<Time> for std::time::SystemTime {
    fn from(time: Time) -> Self {
        let timestamp = time.0.timestamp();
        let nanos = time.0.timestamp_subsec_nanos();
        std::time::UNIX_EPOCH + std::time::Duration::new(timestamp as u64, nanos)
    }
}

/// MicroTime 是微秒精度的时间
pub type MicroTime = Time;

/// UID 类型
pub type UID = String;

pub type UserInfo = authnv1::UserInfo;

/// Unknown 类型表示未知的序列化数据
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Unknown {
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_encoding: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
}

// ========== 时间序列化模块 ==========
mod time_serde {
    use chrono::{DateTime, Utc};
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(date: &DateTime<Utc>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = date.to_rfc3339();
        serializer.serialize_str(&s)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<DateTime<Utc>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(DateTime::parse_from_rfc3339(&s)
            .map_err(serde::de::Error::custom)?
            .with_timezone(&Utc))
    }
}

// ========== 以下是审计特定的类型定义（保持不变） ==========

/// 审计系统使用的 HTTP 头键
pub mod headers {
    /// 当请求在服务层级中传播时，用于保存审计 ID 的头部。
    /// Audit-ID 头部应由第一个接收请求的服务器设置（例如联邦服务器或 kube-aggregator）。
    ///
    /// 审计 ID 也会通过 HTTP 响应头返回给客户端。
    /// 不能保证所有请求都会发送 Audit-ID HTTP 头。当 kube-apiserver 根据审计策略不审计事件时，
    /// 不会返回 Audit-ID。此外，对于 pods/exec、pods/attach、pods/proxy 的请求，
    /// kube-apiserver 像代理一样工作并将请求重定向到 kubelet 节点，
    /// 用户只会收到从 kubelet 节点发送的 HTTP 头，因此当用户运行类似 "kubectl exec" 或
    /// "kubectl attach" 的命令时，不会发送 Audit-ID。
    pub const AUDIT_ID: &str = "Audit-ID";
}

/// 定义审计期间记录的信息量级别
/// Level defines the amount of information logged during auditing.
///
/// The levels are ordered: `None` < `Metadata` < `Request` < `RequestResponse`
#[derive(Debug, Default, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum Level {
    /// LevelNone 禁用审计
    #[default]
    None,
    /// LevelMetadata 提供基本的审计级别
    Metadata,
    /// LevelRequest 提供 Metadata 级别的审计，并额外记录请求对象（不适用于非资源请求）
    Request,
    /// LevelRequestResponse 提供 Request 级别的审计，并额外记录响应对象（不适用于非资源请求）
    RequestResponse,
}

impl Level {
    /// 将级别转换为字符串
    pub fn as_str(&self) -> &'static str {
        match self {
            Level::None => "None",
            Level::Metadata => "Metadata",
            Level::Request => "Request",
            Level::RequestResponse => "RequestResponse",
        }
    }
}

impl std::fmt::Display for Level {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// 定义可能生成审计事件的请求处理阶段
#[derive(Debug, Default, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum Stage {
    /// StageRequestReceived: 审计处理程序接收到请求后立即生成事件的阶段，在请求被委派到处理程序链之前
    #[default]
    RequestReceived,
    /// StageResponseStarted: 响应头已发送但响应体尚未发送时生成事件的阶段。此阶段仅针对长时间运行的请求（例如 watch）生成
    ResponseStarted,
    /// StageResponseComplete: 响应体已完成且不会再发送字节时生成事件的阶段
    ResponseComplete,
    /// StagePanic: 发生 panic 时生成事件的阶段
    Panic,
}

impl Stage {
    /// 将阶段转换为字符串
    pub fn as_str(&self) -> &'static str {
        match self {
            Stage::RequestReceived => "RequestReceived",
            Stage::ResponseStarted => "ResponseStarted",
            Stage::ResponseComplete => "ResponseComplete",
            Stage::Panic => "Panic",
        }
    }
}

impl std::fmt::Display for Stage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// 捕获可以包含在 API 审计日志中的所有信息的事件
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Event {
    #[serde(flatten)]
    pub type_meta: TypeMeta,

    /// 生成事件时的审计级别
    pub level: Level,

    /// 唯一的审计 ID，为每个请求生成
    pub audit_id: UID,

    /// 生成此事件实例时的请求处理阶段
    pub stage: Stage,

    /// RequestURI 是客户端发送给服务器的请求 URI
    pub request_uri: String,

    /// Verb 是与请求关联的 Kubernetes 操作动词
    /// 对于非资源请求，这是小写的 HTTP 方法
    pub verb: String,

    /// 已认证的用户信息
    pub user: authnv1::UserInfo,

    /// 被模拟的用户信息
    #[serde(skip_serializing_if = "Option::is_none")]
    pub impersonated_user: Option<Box<authnv1::UserInfo>>,

    /// 源 IP 地址，请求来源和中间代理
    /// 源 IP 地址按以下顺序列出：
    /// 1. X-Forwarded-For 请求头中的 IP
    /// 2. X-Real-Ip 头，如果不在 X-Forwarded-For 列表中
    /// 3. 连接的远程地址，如果与到目前为止列表中的最后一个 IP 不匹配（X-Forwarded-For 或 X-Real-Ip）
    /// 注意：除最后一个 IP 外，所有 IP 都可以由客户端任意设置
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub source_ips: Vec<String>,

    /// UserAgent 记录客户端报告的用户代理字符串
    /// 注意：UserAgent 由客户端提供，不能信任
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,

    /// 此请求针对的对象引用
    /// 不适用于 List 类型请求或非资源请求
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_ref: Option<ObjectReference>,

    /// 响应状态，即使 ResponseObject 不是 Status 类型也会填充
    /// 对于成功的响应，这只包括 Code。对于非状态类型的错误响应，
    /// 这将自动填充错误消息
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_status: Option<Status>,

    /// 请求中的 API 对象，JSON 格式。RequestObject 按原样记录在请求中
    /// （可能重新编码为 JSON），在版本转换、默认值设置、准入控制或合并之前。
    /// 它是一个外部版本化的对象类型，可能本身不是有效的对象。
    /// 对于非资源请求省略。仅在 Request 级别及更高级别记录。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_object: Option<Unknown>,

    /// 响应中返回的 API 对象，JSON 格式。ResponseObject 在转换为外部类型后记录，
    /// 并序列化为 JSON。对于非资源请求省略。仅在 Response 级别记录。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_object: Option<Unknown>,

    /// 请求到达 apiserver 的时间
    pub request_received_timestamp: MicroTime,

    /// 请求到达当前审计阶段的时间
    pub stage_timestamp: MicroTime,

    /// Annotations 是与审计事件一起存储的非结构化键值映射，
    /// 可以由请求服务链中调用的插件设置，包括身份验证、授权和准入插件。
    /// 注意：这些注释是针对审计事件的，与提交对象的 metadata.annotations 不对应。
    /// 键应唯一标识通知组件以避免名称冲突（例如 podsecuritypolicy.admission.k8s.io/policy）。
    /// 值应简短。注释包含在 Metadata 级别中。
    #[serde(skip_serializing_if = "::std::collections::HashMap::is_empty", default)]
    pub annotations: ::std::collections::HashMap<String, String>,
}

impl Default for Event {
    fn default() -> Self {
        Event {
            type_meta: TypeMeta {
                api_version: Some("audit.k8s.io/v1".to_string()),
                kind: Some("Event".to_string()),
            },
            level: Level::default(),
            audit_id: "".to_string(),
            stage: Stage::default(),
            request_uri: "".to_string(),
            verb: "".to_string(),
            user: authnv1::UserInfo::default(),
            impersonated_user: None,
            source_ips: Vec::new(),
            user_agent: None,
            object_ref: None,
            response_status: None,
            request_object: None,
            response_object: None,
            request_received_timestamp: MicroTime::default(),
            stage_timestamp: MicroTime::default(),
            annotations: ::std::collections::HashMap::new(),
        }
    }
}
/// AuditEvent captures all the information that can be included in an API audit log.
///
/// # Examples
///
/// ```
/// use k8s_audit_apis::audit;
///
/// let event = audit::Event {
///     audit_id: "test-123".into(),
///     request_uri: "/api/v1/pods".to_string(),
///     verb: "list".to_string(),
///     level: audit::Level::Metadata,
///     stage: audit::Stage::RequestReceived,
///     ..Default::default()
/// };
///
/// assert_eq!(event.audit_id, "test-123");
/// assert_eq!(event.level, audit::Level::Metadata);
/// ```
/// 审计事件列表
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct EventList {
    #[serde(flatten)]
    pub type_meta: TypeMeta,

    #[serde(flatten)]
    pub list_meta: Option<ListMeta>,

    pub items: Vec<Event>,
}

/// 定义审计日志的配置，以及不同请求类别如何记录的规则
/// Policy defines the configuration of audit logging.
///
/// A policy consists of ordered rules that specify what should be audited
/// and at what level.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Policy {
    #[serde(flatten)]
    pub type_meta: TypeMeta,

    /// ObjectMeta 包含用于与 API 基础设施互操作
    #[serde(flatten)]
    pub object_meta: Option<ObjectMeta>,

    /// Rules 指定应记录请求的审计级别
    /// 一个请求可能匹配多个规则，在这种情况下使用第一个匹配的规则
    /// 默认审计级别为 None，但可以通过列表末尾的通配符规则覆盖
    /// PolicyRules 是严格有序的
    pub rules: Vec<PolicyRule>,

    /// OmitStages 是不创建事件的阶段列表
    /// 注意：这也可以在每条规则中指定，在这种情况下，两者的并集被省略
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub omit_stages: Vec<Stage>,

    /// OmitManagedFields 指示是否从写入 API 审计日志的请求和响应体中省略托管字段
    /// 这用作全局默认值 - 'true' 值将省略托管字段，
    /// 否则托管字段将包含在 API 审计日志中
    /// 注意：这也可以在每条规则中指定，在这种情况下，规则中指定的值将覆盖全局默认值
    #[serde(skip_serializing_if = "Option::is_none")]
    pub omit_managed_fields: Option<bool>,
}

/// 审计策略列表
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PolicyList {
    #[serde(flatten)]
    pub type_meta: TypeMeta,

    #[serde(flatten)]
    pub list_meta: Option<ListMeta>,

    pub items: Vec<Policy>,
}

/// PolicyRule 根据元数据将请求映射到审计级别
/// 请求必须匹配每个字段的规则（规则的交集）
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PolicyRule {
    /// 与此规则匹配的请求记录的级别
    pub level: Level,

    /// 此规则适用的用户（按已验证的用户名）
    /// 空列表表示每个用户
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub users: Vec<String>,

    /// 此规则适用的用户组。如果用户是任何 UserGroups 的成员，则认为匹配
    /// 空列表表示每个用户组
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub user_groups: Vec<String>,

    /// 与此规则匹配的操作动词
    /// 空列表表示每个动词
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub verbs: Vec<String>,

    /// 规则可以应用于 API 资源（如 "pods" 或 "secrets"）、
    /// 非资源 URL 路径（如 "/api"），或者两者都不，但不能同时应用两者
    /// 如果两者都未指定，则该规则被视为所有 URL 的默认规则

    /// 此规则匹配的资源。空列表表示所有 API 组中的所有种类
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub resources: Vec<GroupResources>,

    /// 此规则匹配的命名空间
    /// 空字符串 "" 匹配非命名空间资源
    /// 空列表表示每个命名空间
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub namespaces: Vec<String>,

    /// NonResourceURLs 是应审计的一组 URL 路径
    /// 允许使用 `*`，但只能作为路径中的完整最后一步
    /// 示例：
    ///  `/metrics` - 记录 apiserver 指标的请求
    ///  `/healthz*` - 记录所有健康检查
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub non_resource_urls: Vec<String>,

    /// OmitStages 是不创建事件的阶段列表
    /// 注意：这也可以在策略范围内指定，在这种情况下，两者的并集被省略
    /// 空列表表示不应用任何限制
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub omit_stages: Vec<Stage>,

    /// OmitManagedFields 指示是否从写入 API 审计日志的请求和响应体中省略托管字段
    /// - 'true' 值将从 API 审计日志中删除托管字段
    /// - 'false' 值表示托管字段应包含在 API 审计日志中
    /// 注意，如果在此规则中指定，此值将覆盖全局默认值
    /// 如果未指定值，则使用 Policy.OmitManagedFields 中指定的全局默认值
    #[serde(skip_serializing_if = "Option::is_none")]
    pub omit_managed_fields: Option<bool>,
}

/// 表示 API 组中的资源种类
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct GroupResources {
    /// Group 是包含资源的 API 组的名称
    /// 空字符串表示核心 API 组
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,

    /// Resources 是此规则适用的资源列表
    ///
    /// 例如：
    /// - `pods` 匹配 pods
    /// - `pods/log` 匹配 pods 的 log 子资源
    /// - `*` 匹配所有资源及其子资源
    /// - `pods/*` 匹配 pods 的所有子资源
    /// - `*/scale` 匹配所有 scale 子资源
    ///
    /// 如果存在通配符，验证规则将确保资源不会相互重叠
    ///
    /// 空列表表示此 API 组中的所有资源和子资源都适用
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub resources: Vec<String>,

    /// ResourceNames 是策略匹配的资源实例名称列表
    /// 使用此字段需要指定 Resources
    /// 空列表表示匹配资源的每个实例
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub resource_names: Vec<String>,
}

/// ObjectReference 包含足够的信息来检查或修改所引用的对象
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ObjectReference {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<UID>,

    /// APIGroup 是包含所引用对象的 API 组的名称
    /// 空字符串表示核心 API 组
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_group: Option<String>,

    /// APIVersion 是包含所引用对象的 API 组的版本
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_version: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_version: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub subresource: Option<String>,
}
