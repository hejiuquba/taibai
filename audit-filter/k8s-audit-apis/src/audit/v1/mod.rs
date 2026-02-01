/*
Copyright 2018 The Kubernetes Authors.
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

//! 审计 API v1 版本

mod types;
mod validation;

pub use validation::*;

// 导入内层类型
use crate::audit::types as audit_inner;

use crate::audit::v1::types::{Event, Level, ObjectReference, Stage};

/// v1 API 版本常量
pub const API_VERSION: &str = "audit.k8s.io/v1";

/// 实现从内层 ObjectReference 到 v1 ObjectReference 的转换
impl From<audit_inner::ObjectReference> for ObjectReference {
    fn from(inner: audit_inner::ObjectReference) -> Self {
        ObjectReference {
            resource: inner.resource,
            namespace: inner.namespace,
            name: inner.name,
            uid: inner.uid, // 注意：这里可能需要类型转换，因为内层的 uid 是 Option<UID>
            api_group: inner.api_group, // 注意字段名可能不同
            api_version: inner.api_version,
            resource_version: inner.resource_version,
            subresource: inner.subresource,
        }
    }
}

/// 实现从 v1 ObjectReference 到内层 ObjectReference 的转换
impl From<ObjectReference> for audit_inner::ObjectReference {
    fn from(v1: ObjectReference) -> Self {
        audit_inner::ObjectReference {
            resource: v1.resource,
            namespace: v1.namespace,
            name: v1.name,
            uid: v1.uid, // 注意类型转换
            api_group: v1.api_group,
            api_version: v1.api_version,
            resource_version: v1.resource_version,
            subresource: v1.subresource,
        }
    }
}

/// 简化版本转换示例
pub fn convert_from_internal(internal: &crate::audit::Event) -> Event {
    Event {
        type_meta: crate::audit::TypeMeta {
            api_version: Some(API_VERSION.to_string()),
            kind: Some("Event".to_string()),
        },
        level: match internal.level {
            crate::audit::Level::None => Level::None,
            crate::audit::Level::Metadata => Level::Metadata,
            crate::audit::Level::Request => Level::Request,
            crate::audit::Level::RequestResponse => Level::RequestResponse,
        },
        audit_id: internal.audit_id.clone(),
        stage: match internal.stage {
            crate::audit::Stage::RequestReceived => Stage::RequestReceived,
            crate::audit::Stage::ResponseStarted => Stage::ResponseStarted,
            crate::audit::Stage::ResponseComplete => Stage::ResponseComplete,
            crate::audit::Stage::Panic => Stage::Panic,
        },
        request_uri: internal.request_uri.clone(),
        verb: internal.verb.clone(),
        user: internal.user.clone(),
        impersonated_user: internal.impersonated_user.clone(),
        source_ips: internal.source_ips.clone(),
        user_agent: internal.user_agent.clone(),
        object_ref: internal.object_ref.clone().map(ObjectReference::from), // 使用 .map() 处理 Option
        response_status: internal.response_status.clone(),
        request_object: internal.request_object.clone(),
        response_object: internal.response_object.clone(),
        request_received_timestamp: internal.request_received_timestamp.clone(),
        stage_timestamp: internal.stage_timestamp.clone(),
        annotations: internal.annotations.clone(),
    }
}

/// 将 v1 版本转换为内部版本
pub fn convert_to_internal(v1_event: &Event) -> crate::audit::Event {
    crate::audit::Event {
        type_meta: crate::audit::TypeMeta {
            api_version: Some(crate::audit::GROUP_NAME.to_string()),
            kind: Some("Event".to_string()),
        },
        level: match v1_event.level {
            Level::None => crate::audit::Level::None,
            Level::Metadata => crate::audit::Level::Metadata,
            Level::Request => crate::audit::Level::Request,
            Level::RequestResponse => crate::audit::Level::RequestResponse,
        },
        audit_id: v1_event.audit_id.clone(),
        stage: match v1_event.stage {
            Stage::RequestReceived => crate::audit::Stage::RequestReceived,
            Stage::ResponseStarted => crate::audit::Stage::ResponseStarted,
            Stage::ResponseComplete => crate::audit::Stage::ResponseComplete,
            Stage::Panic => crate::audit::Stage::Panic,
        },
        request_uri: v1_event.request_uri.clone(),
        verb: v1_event.verb.clone(),
        user: v1_event.user.clone(),
        impersonated_user: v1_event.impersonated_user.clone(),
        source_ips: v1_event.source_ips.clone(),
        user_agent: v1_event.user_agent.clone(),
        object_ref: v1_event
            .object_ref
            .clone()
            .map(audit_inner::ObjectReference::from), // 使用 .map() 处理 Option
        response_status: v1_event.response_status.clone(),
        request_object: v1_event.request_object.clone(),
        response_object: v1_event.response_object.clone(),
        request_received_timestamp: v1_event.request_received_timestamp.clone(),
        stage_timestamp: v1_event.stage_timestamp.clone(),
        annotations: v1_event.annotations.clone(),
    }
}
