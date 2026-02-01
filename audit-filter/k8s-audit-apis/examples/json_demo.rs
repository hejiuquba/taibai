/*
Copyright 2024 The Kubernetes Authors.
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

//! JSON serialization example for k8s-audit-apis
//!
//! This example shows how to serialize and deserialize audit types to/from JSON.

use k8s_audit_apis::audit;
use serde_json;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== JSON Serialization Demo ===\n");

    // 1. Create sample data
    println!("1. Creating sample audit data...");
    let event = create_sample_event();
    let policy = create_sample_policy();

    // 2. Serialize to JSON
    println!("\n2. Serializing to JSON...");

    let event_json = serde_json::to_string_pretty(&event)?;
    println!("   Event JSON:");
    println!("{}", event_json);

    let policy_json = serde_json::to_string_pretty(&policy)?;
    println!("\n   Policy JSON (first 300 chars):");
    println!("{}", &policy_json[..std::cmp::min(300, policy_json.len())]);
    if policy_json.len() > 300 {
        println!("   ... (truncated)");
    }

    // 3. Deserialize from JSON
    println!("\n3. Deserializing from JSON...");

    let decoded_event: audit::Event = serde_json::from_str(&event_json)?;
    println!("   Event deserialized successfully");
    println!(
        "   ID: {}, Level: {:?}",
        decoded_event.audit_id, decoded_event.level
    );

    let decoded_policy: audit::Policy = serde_json::from_str(&policy_json)?;
    println!(
        "   Policy deserialized with {} rules",
        decoded_policy.rules.len()
    );

    // 4. Round-trip test
    println!("\n4. Round-trip test...");

    let re_encoded = serde_json::to_string(&decoded_event)?;
    let round_trip: audit::Event = serde_json::from_str(&re_encoded)?;

    assert_eq!(event.audit_id, round_trip.audit_id);
    assert_eq!(event.level, round_trip.level);
    println!("   Round-trip successful!");

    println!("\n=== Demo completed ===");
    Ok(())
}

fn create_sample_event() -> audit::Event {
    use k8s_openapi::api::authentication::v1::UserInfo;

    audit::Event {
        type_meta: audit::TypeMeta {
            api_version: Some("audit.k8s.io/v1".to_string()),
            kind: Some("Event".to_string()),
        },
        level: audit::Level::RequestResponse,
        audit_id: "a1b2c3d4-e5f6-7890-abcd-ef1234567890".to_string(),
        stage: audit::Stage::ResponseComplete,
        request_uri: "/api/v1/namespaces/production/pods".to_string(),
        verb: "create".to_string(),
        user: UserInfo {
            username: Some("system:serviceaccount:kube-system:default".to_string()),
            uid: Some("a1b2c3d4".to_string()),
            groups: Some(vec![
                "system:serviceaccounts".to_string(),
                "system:serviceaccounts:kube-system".to_string(),
            ]),
            // 修复：包装在 Some 中
            extra: Some(std::collections::BTreeMap::from([(
                "authentication.kubernetes.io/pod-name".to_string(),
                vec!["pod-xyz".to_string()],
            )])),
            ..Default::default()
        },
        source_ips: vec!["10.0.0.1".to_string(), "192.168.1.100".to_string()],
        user_agent: Some("Go-http-client/1.1".to_string()),
        object_ref: Some(audit::ObjectReference {
            resource: Some("pods".to_string()),
            namespace: Some("production".to_string()),
            name: Some("web-server".to_string()),
            ..Default::default()
        }),
        response_status: Some(audit::Status {
            status: Some("Failure".to_string()),
            message: Some("pod already exists".to_string()),
            reason: Some("AlreadyExists".to_string()),
            code: Some(409),
            ..Default::default()
        }),
        request_received_timestamp: audit::Time::default(),
        stage_timestamp: audit::Time::default(),
        annotations: std::collections::HashMap::from([
            (
                "authorization.k8s.io/decision".to_string(),
                "allow".to_string(),
            ),
            (
                "authorization.k8s.io/reason".to_string(),
                "RBAC: allowed by ClusterRoleBinding".to_string(),
            ),
        ]),
        ..Default::default()
    }
}

fn create_sample_policy() -> audit::Policy {
    audit::Policy {
        type_meta: audit::TypeMeta {
            api_version: Some("audit.k8s.io/v1".to_string()),
            kind: Some("Policy".to_string()),
        },
        object_meta: Some(audit::ObjectMeta {
            name: Some("default-audit-policy".to_string()),
            ..Default::default()
        }),
        rules: vec![audit::PolicyRule {
            level: audit::Level::RequestResponse,
            users: vec!["admin".to_string()],
            user_groups: vec!["system:masters".to_string()],
            verbs: vec!["*".to_string()],
            resources: vec![audit::GroupResources {
                group: Some("".to_string()),
                resources: vec!["secrets".to_string()],
                resource_names: vec!["default-token-.*".to_string()],
            }],
            omit_stages: vec![audit::Stage::Panic],
            ..Default::default()
        }],
        omit_stages: vec![audit::Stage::Panic],
        omit_managed_fields: Some(true),
    }
}
