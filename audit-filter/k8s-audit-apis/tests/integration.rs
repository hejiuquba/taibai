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

use k8s_audit_apis::audit;

/// Comprehensive integration tests for the audit API
#[test]
fn test_comprehensive_audit_workflow() {
    // 1. Create a complex policy
    let policy = create_test_policy();

    // 2. Create audit events that would match the policy
    let admin_event = create_admin_event();
    let healthcheck_event = create_healthcheck_event();

    // 3. Verify event properties
    assert_eq!(admin_event.user.username.as_deref(), Some("admin"));
    assert_eq!(healthcheck_event.request_uri, "/healthz");

    // 4. Test ordering of events by level
    let mut events = vec![
        create_low_level_event(),
        create_high_level_event(),
        create_medium_level_event(),
    ];

    // Sort by level
    events.sort_by(|a, b| a.level.cmp(&b.level));

    // Verify order: None < Metadata < Request < RequestResponse
    assert!(events[0].level == audit::Level::None || events[0].level == audit::Level::Metadata);
    assert!(
        events[events.len() - 1].level == audit::Level::Request
            || events[events.len() - 1].level == audit::Level::RequestResponse
    );
}

fn create_test_policy() -> audit::Policy {
    audit::Policy {
        rules: vec![
            // Admin rule
            audit::PolicyRule {
                level: audit::Level::RequestResponse,
                users: vec!["admin".to_string()],
                verbs: vec![
                    "create".to_string(),
                    "update".to_string(),
                    "delete".to_string(),
                ],
                resources: vec![
                    audit::GroupResources {
                        group: Some("".to_string()),
                        resources: vec!["secrets".to_string(), "configmaps".to_string()],
                        ..Default::default()
                    },
                    audit::GroupResources {
                        group: Some("apps".to_string()),
                        resources: vec!["deployments".to_string()],
                        ..Default::default()
                    },
                ],
                namespaces: vec!["production".to_string(), "default".to_string()],
                ..Default::default()
            },
            // Health check rule
            audit::PolicyRule {
                level: audit::Level::Metadata,
                non_resource_urls: vec!["/healthz".to_string(), "/readyz".to_string()],
                ..Default::default()
            },
            // Default rule (catch-all)
            audit::PolicyRule {
                level: audit::Level::None,
                ..Default::default()
            },
        ],
        omit_stages: vec![audit::Stage::Panic],
        omit_managed_fields: Some(false),
        ..Default::default()
    }
}

fn create_admin_event() -> audit::Event {
    use k8s_openapi::api::authentication::v1::UserInfo;

    audit::Event {
        audit_id: "admin-event-123".into(),
        request_uri: "/api/v1/namespaces/production/secrets".to_string(),
        verb: "create".to_string(),
        level: audit::Level::RequestResponse,
        stage: audit::Stage::ResponseComplete,
        user: UserInfo {
            username: Some("admin".to_string()),
            groups: Some(vec!["system:masters".to_string()]),
            ..Default::default()
        },
        object_ref: Some(audit::ObjectReference {
            resource: Some("secrets".to_string()),
            namespace: Some("production".to_string()),
            name: Some("database-password".to_string()),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn create_healthcheck_event() -> audit::Event {
    audit::Event {
        audit_id: "healthcheck-456".into(),
        request_uri: "/healthz".to_string(),
        verb: "get".to_string(),
        level: audit::Level::Metadata,
        stage: audit::Stage::RequestReceived,
        user: k8s_openapi::api::authentication::v1::UserInfo::default(),
        source_ips: vec!["127.0.0.1".to_string()],
        ..Default::default()
    }
}

fn create_low_level_event() -> audit::Event {
    audit::Event {
        audit_id: "low-level".into(),
        level: audit::Level::None,
        ..Default::default()
    }
}

fn create_medium_level_event() -> audit::Event {
    audit::Event {
        audit_id: "medium-level".into(),
        level: audit::Level::Request,
        ..Default::default()
    }
}

fn create_high_level_event() -> audit::Event {
    audit::Event {
        audit_id: "high-level".into(),
        level: audit::Level::RequestResponse,
        ..Default::default()
    }
}

#[test]
fn test_thread_safety() {
    use std::sync::Arc;
    use std::thread;

    // Test that types can be shared between threads
    let policy = Arc::new(audit::Policy::default());

    let mut handles = vec![];

    for i in 0..5 {
        let policy_clone = Arc::clone(&policy);
        handles.push(thread::spawn(move || {
            // Just read the policy
            let rule_count = policy_clone.rules.len();
            println!("Thread {}: rule count = {}", i, rule_count);
            assert_eq!(rule_count, 0);
        }));
    }

    for handle in handles {
        handle.join().expect("Thread panicked");
    }
}
