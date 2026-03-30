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

mod audit;

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::SystemTime;

use k8s_openapi::api::authentication::v1 as authnv1;
use kube::core::{self, ObjectMeta};
use kube::runtime::{self, NegotiatedSerializer};
use kube::api::{GroupVersion, GroupVersionResource};
use crate::auditinternal;
use crate::authorizer;
use crate::user;
use log::error;

const MAX_USER_AGENT_LENGTH: usize = 1024;
const USER_AGENT_TRUNCATE_SUFFIX: &str = "...TRUNCATED";

pub fn log_request_metadata(
    ctx: &core::Context,
    req: &http::Request<()>,
    request_received_timestamp: SystemTime,
    attribs: &dyn authorizer::Attributes,
) {
    let ac = audit::audit_context_from(ctx);
    if !ac.enabled() {
        return;
    }

    ac.visit_event(|ev: &mut auditinternal::Event| {
        ev.request_received_timestamp = Some(request_received_timestamp.into());
        ev.verb = attribs.get_verb();
        ev.request_uri = req.uri().to_string();
        ev.user_agent = maybe_truncate_user_agent(req);

        let ips: Vec<IpAddr> = req.source_ips();
        ev.source_ips = ips.iter().map(|ip| ip.to_string()).collect();

        if let Some(user) = attribs.get_user() {
            ev.user.username = user.get_name().to_string();
            ev.user.extra = user.get_extra().iter()
                .map(|(k, v)| (k.clone(), authnv1::ExtraValue(v.clone())))
                .collect();
            ev.user.groups = user.get_groups().to_vec();
            ev.user.uid = user.get_uid().to_string();
        }

        if attribs.is_resource_request() {
            ev.object_ref = Some(auditinternal::ObjectReference {
                namespace: attribs.get_namespace().to_string(),
                name: attribs.get_name().to_string(),
                resource: attribs.get_resource().to_string(),
                subresource: attribs.get_subresource().to_string(),
                api_group: attribs.get_api_group().to_string(),
                api_version: attribs.get_api_version().to_string(),
            });
        }
    });
}

// LogImpersonatedUser fills in the impersonated user attributes into an audit event.
pub fn log_impersonated_user(ctx: &core::Context, user: &dyn user::Info, constraint: &str) {
    let ac = audit::audit_context_from(ctx);
    if !ac.enabled() {
        return;
    }
    ac.log_impersonated_user(user, constraint);
}

// LogRequestObject fills in the request object into an audit event. The passed runtime.Object
// will be converted to the given gv.
pub fn log_request_object(
    ctx: &core::Context,
    obj: &dyn runtime::Object,
    obj_gv: &GroupVersion,
    gvr: &GroupVersionResource,
    subresource: &str,
    serializer: &NegotiatedSerializer,
) {
    let ac = audit::audit_context_from(ctx);
    if !ac.enabled() {
        return;
    }
    if ac.get_event_level().less(auditinternal::Level::Metadata) {
        return;
    }

    // meta.Accessor is more general than ObjectMetaAccessor, but if it fails, we can just skip setting these bits
    let obj_meta = meta_accessor(obj).ok();
    if should_omit_managed_fields(&ac) {
        if let Ok((copy, ok)) = copy_without_managed_fields(obj) {
            if ok {
                obj = copy;
            }
        }
    }

    // TODO(audit): hook into the serializer to avoid double conversion
    let request_object = match encode_object(obj, obj_gv, serializer) {
        Ok(obj) => obj,
        Err(err) => {
            error!("Encoding failed of request object: {:?}", err);
            return;
        }
    };

    ac.visit_event(|ae: &mut auditinternal::Event| {
        if ae.object_ref.is_none() {
            ae.object_ref = Some(auditinternal::ObjectReference::default());
        }

        if let Some(meta) = obj_meta {
            if ae.object_ref.as_ref().unwrap().namespace.is_empty() {
                ae.object_ref.as_mut().unwrap().namespace = meta.namespace().to_string();
            }
            if ae.object_ref.as_ref().unwrap().name.is_empty() {
                ae.object_ref.as_mut().unwrap().name = meta.name().to_string();
            }
            if ae.object_ref.as_ref().unwrap().uid.is_empty() {
                ae.object_ref.as_mut().unwrap().uid = meta.uid().to_string();
            }
            if ae.object_ref.as_ref().unwrap().resource_version.is_empty() {
                ae.object_ref.as_mut().unwrap().resource_version = meta.resource_version().to_string();
            }
        }
        if ae.object_ref.as_ref().unwrap().api_version.is_empty() {
            ae.object_ref.as_mut().unwrap().api_group = gvr.group().to_string();
            ae.object_ref.as_mut().unwrap().api_version = gvr.version().to_string();
        }
        if ae.object_ref.as_ref().unwrap().resource.is_empty() {
            ae.object_ref.as_mut().unwrap().resource = gvr.resource().to_string();
        }
        if ae.object_ref.as_ref().unwrap().subresource.is_empty() {
            ae.object_ref.as_mut().unwrap().subresource = subresource.to_string();
        }

        if ae.level.less(auditinternal::Level::Request) {
            return;
        }
        ae.request_object = Some(request_object);
    });
}

// LogRequestPatch fills in the given patch as the request object into an audit event.
pub fn log_request_patch(ctx: &core::Context, patch: &[u8]) {
    let ac = audit::audit_context_from(ctx);
    if ac.get_event_level().less(auditinternal::Level::Request) {
        return;
    }
    ac.log_request_patch(patch);
}

// LogResponseObject fills in the response object into an audit event. The passed runtime.Object
// will be converted to the given gv.
pub fn log_response_object(
    ctx: &core::Context,
    obj: &dyn runtime::Object,
    gv: &GroupVersion,
    serializer: &NegotiatedSerializer,
) {
    let ac = audit::audit_context_from(ctx);
    let status: Option<&metav1::Status> = obj.downcast_ref::<metav1::Status>();
    if ac.get_event_level().less(auditinternal::Level::Metadata) {
        return;
    } else if ac.get_event_level().less(auditinternal::Level::RequestResponse) {
        ac.log_response_object(status, None);
        return;
    }

    if should_omit_managed_fields(&ac) {
        if let Ok((copy, ok)) = copy_without_managed_fields(obj) {
            if ok {
                obj = copy;
            }
        }
    }

    // TODO(audit): hook into the serializer to avoid double conversion
    let response_object = match encode_object(obj, gv, serializer) {
        Ok(obj) => obj,
        Err(err) => {
            error!("Encoding failed of response object: {:?}", err);
            return;
        }
    };
    ac.log_response_object(status, Some(response_object));
}

fn encode_object(obj: &dyn runtime::Object, gv: &GroupVersion, serializer: &NegotiatedSerializer) -> Result<runtime::Unknown, String> {
    const MEDIA_TYPE: &str = "application/json";
    let info = serializer.info_for_media_type(MEDIA_TYPE).ok_or_else(|| {
        format!("unable to locate encoder -- {} is not a supported media type", MEDIA_TYPE)
    })?;

    let enc = serializer.encoder_for_version(info.serializer, gv);
    let mut buf = Vec::new();
    if let Err(err) = enc.encode(obj, &mut buf) {
        return Err(format!("encoding failed: {:?}", err));
    }

    Ok(runtime::Unknown {
        raw: buf,
        content_type: MEDIA_TYPE.to_string(),
    })
}

// truncate User-Agent if too long, otherwise return it directly.
fn maybe_truncate_user_agent(req: &http::Request<()>) -> String {
    let ua = req.headers().get("User-Agent").and_then(|h| h.to_str().ok()).unwrap_or("");
    if ua.len() > MAX_USER_AGENT_LENGTH {
        return format!("{}{}", &ua[..MAX_USER_AGENT_LENGTH], USER_AGENT_TRUNCATE_SUFFIX);
    }
    ua.to_string()
}

// copy_without_managed_fields will make a deep copy of the specified object and
// will discard the managed fields from the copy.
// The specified object is expected to be a meta.Object or a "list".
// The specified object obj is treated as readonly and hence not mutated.
// On return, an error is set if the function runs into any error while
// removing the managed fields, the boolean value is true if the copy has
// been made successfully, otherwise false.
fn copy_without_managed_fields(obj: &dyn runtime::Object) -> Result<(Box<dyn runtime::Object>, bool), Box<dyn std::error::Error>> {
    let is_accessor = meta_accessor(obj).is_ok();
    let is_list = meta_is_list_type(obj);
    let is_table = obj.is::<metav1::Table>();
    if !is_accessor && !is_list && !is_table {
        return Ok((Box::new(obj.clone()), false));
    }

    // TODO a deep copy isn't really needed here, figure out how we can reliably
    //  use shallow copy here to omit the manageFields.
    let copy = obj.deep_copy_object();

    if is_accessor {
        remove_managed_fields(&copy)?;
    }

    if is_list {
        meta_each_list_item(&copy, remove_managed_fields)?;
    }

    if is_table {
        let table = copy.downcast_ref::<metav1::Table>().unwrap();
        for row in &table.rows {
            let row_obj = row.object();
            remove_managed_fields(row_obj)?;
        }
    }

    Ok((copy, true))
}

fn remove_managed_fields(obj: &dyn runtime::Object) -> Result<(), Box<dyn std::error::Error>> {
    if obj.is_none() {
        return Ok(());
    }
    let accessor = meta_accessor(obj)?;
    accessor.set_managed_fields(None);
    Ok(())
}

fn should_omit_managed_fields(ac: &audit::AuditContext) -> bool {
    if ac.initialized.load(Ordering::SeqCst) && ac.request_audit_config.omit_managed_fields {
        return true;
    }
    // If we can't decide, return false to maintain current behavior which is
    // to retain the manage fields in the audit.
    false
}
