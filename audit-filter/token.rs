// Copyright 2018 The Kubernetes Authors.
// Licensed under the Apache License, Version 2.0

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use k8s_openapi::api::authentication::v1 as authenticationv1;
use k8s_openapi::api::core::v1::{Node, Pod, Secret, ServiceAccount};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{CreateOptions, GetOptions, ObjectMeta, Time};
use k8s_openapi::apimachinery::pkg::runtime::schema::GroupVersionKind;
use k8s_openapi::apimachinery::pkg::types::UID;

use crate::audit;
use crate::authentication::authenticator::Audiences;
use crate::authentication::serviceaccount;
use crate::authentication::token::jwt;
use crate::errors::{ApiError, ErrorKind};
use crate::features::{FeatureGate, GenericFeatures, KubernetesFeatures};
use crate::registry::rest::{Getter, NamedCreater, GroupVersionKindProvider, SubresourceObjectMetaPreserver};
use crate::request::{Context, NamespaceFrom, RequestInfo, WithRequestInfo};
use crate::token::{TokenGenerator, Claims};
use crate::validation::field::{ErrorList, Invalid, Path};
use crate::warning;

/// TokenREST implements the REST endpoint for ServiceAccount token creation
pub struct TokenREST {
    svcaccts: Arc<dyn Getter>,
    pods: Arc<dyn Getter>,
    secrets: Arc<dyn Getter>,
    nodes: Arc<dyn Getter>,
    issuer: Arc<dyn TokenGenerator>,
    auds: Audiences,
    auds_set: HashSet<String>,
    max_expiration_seconds: i64,
    extend_expiration: bool,
    max_extended_expiration_seconds: i64,
}

/// GroupVersionKind constant for TokenRequest
const GVK: GroupVersionKind = GroupVersionKind {
    group: "authentication.k8s.io",
    version: "v1",
    kind: "TokenRequest",
};

impl TokenREST {
    pub fn new(
        svcaccts: Arc<dyn Getter>,
        pods: Arc<dyn Getter>,
        secrets: Arc<dyn Getter>,
        nodes: Arc<dyn Getter>,
        issuer: Arc<dyn TokenGenerator>,
        auds: Audiences,
        max_expiration_seconds: i64,
        extend_expiration: bool,
        max_extended_expiration_seconds: i64,
    ) -> Self {
        let auds_set: HashSet<String> = auds.iter().cloned().collect();
        
        Self {
            svcaccts,
            pods,
            secrets,
            nodes,
            issuer,
            auds: auds.clone(),
            auds_set,
            max_expiration_seconds,
            extend_expiration,
            max_extended_expiration_seconds,
        }
    }

    /// Create a new TokenRequest
    pub async fn create(
        &self,
        ctx: Context,
        name: String,
        obj: TokenRequest,
        create_validation: Option<Box<dyn ValidateObjectFunc>>,
        _options: Option<CreateOptions>,
    ) -> Result<TokenRequest, ApiError> {
        let mut req = obj;

        // Get the namespace from the context (populated from the URL)
        let namespace = NamespaceFrom(&ctx)
            .ok_or_else(|| ApiError::bad_request("namespace is required"))?;

        // Require name/namespace in the body to match URL if specified
        if !req.metadata.name.is_empty() && req.metadata.name != name {
            let errs = ErrorList::from(vec![
                Invalid::new(
                    Path::new("metadata").child("name"),
                    &req.metadata.name,
                    "must match the service account name if specified",
                )
            ]);
            return Err(ApiError::invalid(GVK.group_kind(), &name, errs));
        }

        if !req.metadata.namespace.is_empty() && req.metadata.namespace != namespace {
            let errs = ErrorList::from(vec![
                Invalid::new(
                    Path::new("metadata").child("namespace"),
                    &req.metadata.namespace,
                    "must match the service account namespace if specified",
                )
            ]);
            return Err(ApiError::invalid(GVK.group_kind(), &name, errs));
        }

        // Lookup service account
        let svcacct_obj = self.svcaccts.get(&ctx, &name, &GetOptions::default()).await?;
        let svcacct = svcacct_obj.as_service_account()?;

        // Validate UID if provided
        if !req.metadata.uid.is_empty() && req.metadata.uid != svcacct.metadata.uid {
            if FeatureGate::default_feature_gate()
                .enabled(GenericFeatures::TokenRequestServiceAccountUIDValidation)
            {
                return Err(ApiError::conflict(
                    GVK.group,
                    GVK.kind,
                    &name,
                    format!(
                        "the UID in the token request ({}) does not match the UID of the service account ({})",
                        req.metadata.uid, svcacct.metadata.uid
                    ),
                ));
            } else {
                audit::add_audit_annotation(
                    &ctx,
                    "authentication.k8s.io/token-request-uid-mismatch",
                    format!(
                        "the UID in the token request ({}) does not match the UID of the service account ({})",
                        req.metadata.uid, svcacct.metadata.uid
                    ),
                );
            }
        }

        // Default unset spec audiences to API server audiences
        if req.spec.audiences.is_empty() {
            req.spec.audiences = self.auds.clone();
        }

        // Populate metadata fields if not set
        if req.metadata.name.is_empty() {
            req.metadata.name = svcacct.metadata.name.clone();
        }
        if req.metadata.namespace.is_empty() {
            req.metadata.namespace = svcacct.metadata.namespace.clone();
        }
        if req.metadata.uid.is_empty() {
            req.metadata.uid = svcacct.metadata.uid.clone();
        } else if req.metadata.uid != svcacct.metadata.uid {
            warning::add_warning(
                &ctx,
                "",
                format!(
                    "the UID in the token request ({}) does not match the UID of the service account ({}) but TokenRequestServiceAccountUIDValidation is not enabled. In the future, this will return a conflict error",
                    req.metadata.uid, svcacct.metadata.uid
                ),
            );
        }

        // Save current time before building the token
        let now_time = SystemTime::now();
        req.metadata.creation_timestamp = Some(Time(now_time));

        // Clear status
        req.status = TokenRequestStatus::default();

        // Call static validation
        if let Err(errs) = validate_token_request(&req) {
            return Err(ApiError::invalid(GVK.group_kind(), "", errs));
        }

        // Call validating admission
        if let Some(validation) = create_validation {
            validation(&ctx, req.deep_copy()).await?;
        }

        let mut pod: Option<Pod> = None;
        let mut node: Option<Node> = None;
        let mut secret: Option<Secret> = None;

        // Handle bound object reference
        if let Some(ref bound_ref) = req.spec.bound_object_ref {
            let mut uid = UID::default();

            let gvk = GroupVersionKind::from_api_version_and_kind(
                &bound_ref.api_version,
                &bound_ref.kind,
            );

            match (gvk.group.as_str(), gvk.kind.as_str()) {
                ("", "Pod") => {
                    let new_ctx = new_context(
                        ctx.clone(),
                        "pods",
                        &bound_ref.name,
                        &namespace,
                        gvk.clone(),
                    );
                    let pod_obj = self.pods.get(&new_ctx, &bound_ref.name, &GetOptions::default()).await?;
                    let p = pod_obj.as_pod()?;

                    if name != p.spec.as_ref().unwrap().service_account_name.as_ref().unwrap() {
                        return Err(ApiError::bad_request(format!(
                            "cannot bind token for serviceaccount {:?} to pod running with different serviceaccount name.",
                            name
                        )));
                    }

                    uid = p.metadata.uid.clone();

                    // Handle node info if feature enabled
                    if FeatureGate::default_feature_gate()
                        .enabled(KubernetesFeatures::ServiceAccountTokenPodNodeInfo)
                    {
                        if let Some(ref node_name) = p.spec.as_ref().unwrap().node_name {
                            let new_ctx = new_context(
                                ctx.clone(),
                                "nodes",
                                node_name,
                                "",
                                GroupVersionKind {
                                    group: "".to_string(),
                                    version: "v1".to_string(),
                                    kind: "Node".to_string(),
                                },
                            );

                            // Try with ResourceVersion=0 first (from cache)
                            let mut get_opts = GetOptions::default();
                            get_opts.resource_version = Some("0".to_string());
                            
                            let node_result = self.nodes.get(&new_ctx, node_name, &get_opts).await;
                            let node_obj = match node_result {
                                Ok(obj) => Ok(obj),
                                Err(_) => {
                                    // Fallback to live lookup
                                    self.nodes.get(&new_ctx, node_name, &GetOptions::default()).await
                                }
                            };

                            match node_obj {
                                Ok(n) => {
                                    node = Some(n.as_node()?);
                                }
                                Err(e) if e.is_not_found() => {
                                    // Node doesn't exist, create minimal node object
                                    log::debug!(
                                        "failed fetching node for pod {}/{}, podUID: {}, nodeName: {}",
                                        p.metadata.namespace.as_ref().unwrap(),
                                        p.metadata.name,
                                        p.metadata.uid,
                                        node_name
                                    );
                                    node = Some(Node {
                                        metadata: ObjectMeta {
                                            name: Some(node_name.clone()),
                                            ..Default::default()
                                        },
                                        ..Default::default()
                                    });
                                }
                                Err(e) => {
                                    return Err(ApiError::internal_error(e));
                                }
                            }
                        }
                    }

                    pod = Some(p);
                }
                ("", "Node") => {
                    if !FeatureGate::default_feature_gate()
                        .enabled(KubernetesFeatures::ServiceAccountTokenNodeBinding)
                    {
                        return Err(ApiError::bad_request(format!(
                            "cannot bind token to a Node object as the {:?} feature-gate is disabled",
                            "ServiceAccountTokenNodeBinding"
                        )));
                    }

                    let new_ctx = new_context(ctx.clone(), "nodes", &bound_ref.name, "", gvk.clone());
                    let node_obj = self.nodes.get(&new_ctx, &bound_ref.name, &GetOptions::default()).await?;
                    let n = node_obj.as_node()?;
                    uid = n.metadata.uid.clone();
                    node = Some(n);
                }
                ("", "Secret") => {
                    let new_ctx = new_context(
                        ctx.clone(),
                        "secrets",
                        &bound_ref.name,
                        &namespace,
                        gvk.clone(),
                    );
                    let secret_obj = self.secrets.get(&new_ctx, &bound_ref.name, &GetOptions::default()).await?;
                    let s = secret_obj.as_secret()?;
                    uid = s.metadata.uid.clone();
                    secret = Some(s);
                }
                _ => {
                    return Err(ApiError::bad_request(format!(
                        "cannot bind token to object of type {}",
                        gvk.to_string()
                    )));
                }
            }

            // Validate bound object UID
            if !bound_ref.uid.is_empty() && uid != bound_ref.uid {
                return Err(ApiError::conflict(
                    gvk.group,
                    gvk.kind,
                    &bound_ref.name,
                    format!(
                        "the UID in the bound object reference ({}) does not match the UID in record. The object might have been deleted and then recreated",
                        bound_ref.uid
                    ),
                ));
            }
        }

        // Handle max expiration
        if self.max_expiration_seconds > 0
            && req.spec.expiration_seconds > self.max_expiration_seconds
        {
            warning::add_warning(
                &ctx,
                "",
                format!(
                    "requested expiration of {} seconds shortened to {} seconds",
                    req.spec.expiration_seconds, self.max_expiration_seconds
                ),
            );
            req.spec.expiration_seconds = self.max_expiration_seconds;
        }

        // Tweak expiration for safe transition of projected service account token
        let mut warn_after: i64 = 0;
        let mut exp = req.spec.expiration_seconds;

        if self.extend_expiration
            && pod.is_some()
            && req.spec.expiration_seconds == WARN_ONLY_BOUND_TOKEN_EXPIRATION_SECONDS
            && self.is_kube_audiences(&req.spec.audiences)
        {
            warn_after = exp;
            exp = self.max_extended_expiration_seconds;
        }

        // Generate token claims
        let (sc, pc) = Claims::new(
            &svcacct,
            pod.as_ref(),
            secret.as_ref(),
            node.as_ref(),
            exp,
            warn_after,
            &req.spec.audiences,
        )?;

        // Generate token
        let tokdata = self.issuer.generate_token(&ctx, &sc, &pc).await
            .map_err(|e| ApiError::internal_error(format!("failed to generate token: {}", e)))?;

        // Populate status
        let mut out = req.deep_copy();
        out.status = TokenRequestStatus {
            token: tokdata,
            expiration_timestamp: Time(
                now_time + Duration::from_secs(out.spec.expiration_seconds as u64)
            ),
        };

        // Add audit annotation for JTI if feature enabled
        if FeatureGate::default_feature_gate()
            .enabled(KubernetesFeatures::ServiceAccountTokenJTI)
            && !sc.id.is_empty()
        {
            audit::add_audit_annotation(
                &ctx,
                serviceaccount::ISSUED_CREDENTIAL_ID_AUDIT_ANNOTATION_KEY,
                jwt::credential_id_for_jti(&sc.id),
            );
        }

        Ok(out)
    }

    /// Check if token audiences are a subset of API server audiences
    fn is_kube_audiences(&self, token_audience: &[String]) -> bool {
        token_audience.iter().all(|aud| self.auds_set.contains(aud))
    }
}

impl NamedCreater for TokenREST {
    type Object = TokenRequest;

    fn new(&self) -> Self::Object {
        TokenRequest::default()
    }
}

impl GroupVersionKindProvider for TokenREST {
    fn group_version_kind(&self, _gv: GroupVersion) -> GroupVersionKind {
        GVK
    }
}

impl SubresourceObjectMetaPreserver for TokenREST {
    fn preserve_request_object_meta_system_fields_on_subresource_create(&self) -> bool {
        true
    }
}

/// Create a new context with updated RequestInfo
fn new_context(
    ctx: Context,
    resource: &str,
    name: &str,
    namespace: &str,
    gvk: GroupVersionKind,
) -> Context {
    let new_info = RequestInfo {
        is_resource_request: true,
        verb: "get".to_string(),
        namespace: namespace.to_string(),
        resource: resource.to_string(),
        name: name.to_string(),
        parts: vec![resource.to_string(), name.to_string()],
        api_group: gvk.group,
        api_version: gvk.version,
    };
    WithRequestInfo(ctx, new_info)
}

// Supporting types and traits

#[derive(Debug, Clone, Default)]
pub struct TokenRequest {
    pub metadata: TokenRequestMetadata,
    pub spec: TokenRequestSpec,
    pub status: TokenRequestStatus,
}

#[derive(Debug, Clone, Default)]
pub struct TokenRequestMetadata {
    pub name: String,
    pub namespace: String,
    pub uid: UID,
    pub creation_timestamp: Option<Time>,
}

#[derive(Debug, Clone, Default)]
pub struct TokenRequestSpec {
    pub audiences: Vec<String>,
    pub expiration_seconds: i64,
    pub bound_object_ref: Option<BoundObjectReference>,
}

#[derive(Debug, Clone, Default)]
pub struct TokenRequestStatus {
    pub token: String,
    pub expiration_timestamp: Time,
}

#[derive(Debug, Clone)]
pub struct BoundObjectReference {
    pub kind: String,
    pub api_version: String,
    pub name: String,
    pub uid: UID,
}

pub trait ValidateObjectFunc: Send + Sync {
    fn validate(&self, ctx: &Context, obj: TokenRequest) -> Result<(), ApiError>;
}

/// Constant for warn-only bound token expiration
const WARN_ONLY_BOUND_TOKEN_EXPIRATION_SECONDS: i64 = 3600;

/// Validate token request
fn validate_token_request(req: &TokenRequest) -> Result<(), ErrorList> {
    // Implementation of validation logic
    // This would mirror authenticationvalidation.ValidateTokenRequest
    Ok(())
}

impl TokenRequest {
    pub fn deep_copy(&self) -> Self {
        self.clone()
    }
}

// Trait implementations for type conversions
pub trait AsServiceAccount {
    fn as_service_account(&self) -> Result<ServiceAccount, ApiError>;
}

pub trait AsPod {
    fn as_pod(&self) -> Result<Pod, ApiError>;
}

pub trait AsNode {
    fn as_node(&self) -> Result<Node, ApiError>;
}

pub trait AsSecret {
    fn as_secret(&self) -> Result<Secret, ApiError>;
}
