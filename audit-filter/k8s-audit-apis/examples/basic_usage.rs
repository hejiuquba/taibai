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

//! Basic usage example for k8s-audit-apis
//!
//! This example demonstrates the basic functionality of the audit API crate.

use k8s_audit_apis::audit;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Kubernetes Audit API Rust Example ===\n");

    // 1. Create an audit event
    println!("1. Creating an audit event...");
    let event = create_audit_event();
    println!("   Event created with ID: {}", event.audit_id);
    println!("   Level: {:?}, Stage: {:?}", event.level, event.stage);
    println!("   Request: {} {}", event.verb, event.request_uri);

    // 2. Create an audit policy
    println!("\n2. Creating an audit policy...");
    let policy = create_audit_policy();
    println!("   Policy created with {} rules", policy.rules.len());

    for (i, rule) in policy.rules.iter().enumerate() {
        println!(
            "   Rule {}: Level={:?}, Users={:?}",
            i + 1,
            rule.level,
            rule.users
        );
    }

    // 3. Demonstrate level comparisons
    println!("\n3. Comparing audit levels...");
    compare_audit_levels();

    // 4. JSON serialization (if serde feature is enabled)
    #[cfg(feature = "serde")]
    {
        println!("\n4. JSON serialization...");
        demonstrate_json_serialization(&event)?;
    }

    println!("\n=== Example completed successfully ===");
    Ok(())
}

fn create_audit_event() -> audit::Event {
    use k8s_openapi::api::authentication::v1::UserInfo;

    audit::Event {
        audit_id: format!("event-{}", uuid::Uuid::new_v4()),
        level: audit::Level::Request,
        stage: audit::Stage::ResponseComplete,
        request_uri: "/apis/apps/v1/namespaces/default/deployments".to_string(),
        verb: "create".to_string(),
        user: UserInfo {
            username: Some("alice@example.com".to_string()),
            uid: Some("12345".to_string()),
            groups: Some(vec!["developers".to_string()]),
            ..Default::default()
        },
        source_ips: vec!["192.168.1.100".to_string()],
        user_agent: Some("kubectl/v1.30.0".to_string()),
        object_ref: Some(audit::ObjectReference {
            resource: Some("deployments".to_string()),
            namespace: Some("default".to_string()),
            name: Some("web-app".to_string()),
            api_group: Some("apps".to_string()),
            api_version: Some("v1".to_string()),
            ..Default::default()
        }),
        response_status: Some(audit::Status {
            status: Some("Success".to_string()),
            code: Some(201),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn create_audit_policy() -> audit::Policy {
    audit::Policy {
        rules: vec![
            // Rule 1: Audit all admin actions at highest level
            audit::PolicyRule {
                level: audit::Level::RequestResponse,
                users: vec!["admin".to_string(), "system:admin".to_string()],
                verbs: vec!["*".to_string()],
                ..Default::default()
            },
            // Rule 2: Audit sensitive resources
            audit::PolicyRule {
                level: audit::Level::Request,
                verbs: vec![
                    "get".to_string(),
                    "list".to_string(),
                    "create".to_string(),
                    "update".to_string(),
                    "delete".to_string(),
                ],
                resources: vec![audit::GroupResources {
                    resources: vec!["secrets".to_string(), "configmaps".to_string()],
                    ..Default::default()
                }],
                ..Default::default()
            },
            // Rule 3: Audit health checks
            audit::PolicyRule {
                level: audit::Level::Metadata,
                non_resource_urls: vec!["/healthz".to_string(), "/readyz".to_string()],
                ..Default::default()
            },
            // Rule 4: Default rule (no auditing for everything else)
            audit::PolicyRule {
                level: audit::Level::None,
                ..Default::default()
            },
        ],
        omit_stages: vec![audit::Stage::Panic],
        omit_managed_fields: Some(true),
        ..Default::default()
    }
}

fn compare_audit_levels() {
    use audit::Level;

    let levels = [
        Level::None,
        Level::Metadata,
        Level::Request,
        Level::RequestResponse,
    ];

    for i in 0..levels.len() {
        for j in 0..levels.len() {
            if i < j {
                println!(
                    "   {:?} < {:?}: {}",
                    levels[i],
                    levels[j],
                    levels[i] < levels[j]
                );
            }
        }
    }
}

#[cfg(feature = "serde")]
fn demonstrate_json_serialization(event: &audit::Event) -> Result<(), Box<dyn std::error::Error>> {
    use serde_json;

    // Serialize to JSON
    let json = serde_json::to_string_pretty(event)?;
    println!("   Event as JSON (first 500 chars):");
    println!("   {}", &json[..std::cmp::min(500, json.len())]);
    if json.len() > 500 {
        println!("   ... (truncated)");
    }

    // Deserialize back
    let decoded: audit::Event = serde_json::from_str(&json)?;
    println!(
        "   Successfully deserialized back, ID: {}",
        decoded.audit_id
    );

    Ok(())
}
