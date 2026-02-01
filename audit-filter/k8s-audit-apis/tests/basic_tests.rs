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
use k8s_audit_apis::LevelExt;

#[test]
fn test_level_ordering() {
    // Test ordinal values
    assert_eq!(audit::Level::None.ordinal(), 0);
    assert_eq!(audit::Level::Metadata.ordinal(), 1);
    assert_eq!(audit::Level::Request.ordinal(), 2);
    assert_eq!(audit::Level::RequestResponse.ordinal(), 3);

    // Test comparison operators
    assert!(audit::Level::None < audit::Level::Metadata);
    assert!(audit::Level::Metadata < audit::Level::Request);
    assert!(audit::Level::Request < audit::Level::RequestResponse);

    // Test helper methods
    assert!(audit::Level::Metadata.less(&audit::Level::Request));
    assert!(audit::Level::RequestResponse.greater_or_equal(&audit::Level::Request));
    assert!(audit::Level::Request.greater_or_equal(&audit::Level::Request));
}

#[test]
fn test_event_creation() {
    let event = audit::Event {
        audit_id: "test-audit-id".into(),
        request_uri: "/api/v1/namespaces/default/pods".to_string(),
        verb: "create".to_string(),
        level: audit::Level::Request,
        stage: audit::Stage::ResponseComplete,
        ..Default::default()
    };

    assert_eq!(event.audit_id, "test-audit-id");
    assert_eq!(event.request_uri, "/api/v1/namespaces/default/pods");
    assert_eq!(event.verb, "create");
    assert_eq!(event.level, audit::Level::Request);
    assert_eq!(event.stage, audit::Stage::ResponseComplete);
}

#[test]
fn test_policy_creation() {
    let policy = audit::Policy {
        rules: vec![
            audit::PolicyRule {
                level: audit::Level::RequestResponse,
                users: vec!["admin".to_string(), "system:admin".to_string()],
                verbs: vec!["*".to_string()],
                resources: vec![audit::GroupResources {
                    group: Some("".to_string()),
                    resources: vec!["*".to_string()],
                    ..Default::default()
                }],
                ..Default::default()
            },
            audit::PolicyRule {
                level: audit::Level::Metadata,
                non_resource_urls: vec!["/healthz".to_string(), "/metrics".to_string()],
                ..Default::default()
            },
        ],
        omit_stages: vec![audit::Stage::Panic],
        omit_managed_fields: Some(true),
        ..Default::default()
    };

    assert_eq!(policy.rules.len(), 2);
    assert_eq!(policy.omit_stages, vec![audit::Stage::Panic]);
    assert_eq!(policy.omit_managed_fields, Some(true));

    let rule1 = &policy.rules[0];
    assert_eq!(rule1.level, audit::Level::RequestResponse);
    assert_eq!(rule1.users, vec!["admin", "system:admin"]);
    assert_eq!(rule1.verbs, vec!["*"]);

    let rule2 = &policy.rules[1];
    assert_eq!(rule2.level, audit::Level::Metadata);
    assert_eq!(rule2.non_resource_urls, vec!["/healthz", "/metrics"]);
}

#[test]
fn test_stage_default() {
    // Test that Stage has a sensible default
    let stage = audit::Stage::default();
    assert_eq!(stage, audit::Stage::RequestReceived);
}

#[test]
fn test_json_serialization() {
    // This test requires serde feature
    #[cfg(feature = "serde")]
    {
        use serde_json;

        let event = audit::Event {
            audit_id: "json-test".into(),
            request_uri: "/test".to_string(),
            verb: "get".to_string(),
            level: audit::Level::Metadata,
            stage: audit::Stage::RequestReceived,
            ..Default::default()
        };

        // Serialize
        let json = serde_json::to_string(&event).expect("Serialization failed");
        assert!(json.contains("json-test"));
        assert!(json.contains("Metadata"));
        assert!(json.contains("RequestReceived"));

        // Deserialize
        let decoded: audit::Event = serde_json::from_str(&json).expect("Deserialization failed");
        assert_eq!(decoded.audit_id, "json-test");
        assert_eq!(decoded.level, audit::Level::Metadata);
        assert_eq!(decoded.stage, audit::Stage::RequestReceived);
    }
}

#[test]
fn test_list_types() {
    let event_list = audit::EventList {
        items: vec![
            audit::Event {
                audit_id: "event-1".into(),
                ..Default::default()
            },
            audit::Event {
                audit_id: "event-2".into(),
                ..Default::default()
            },
        ],
        ..Default::default()
    };

    assert_eq!(event_list.items.len(), 2);
    assert_eq!(event_list.items[0].audit_id, "event-1");
    assert_eq!(event_list.items[1].audit_id, "event-2");

    let policy_list = audit::PolicyList {
        items: vec![audit::Policy::default()],
        ..Default::default()
    };

    assert_eq!(policy_list.items.len(), 1);
}
