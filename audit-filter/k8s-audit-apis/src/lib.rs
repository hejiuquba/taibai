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

//! # Kubernetes Audit API for Rust
//!
//! This crate provides Rust types for Kubernetes Audit Logging API, translated from the
//! original Go implementation in the Kubernetes project.
//!
//! ## Features
//!
//! - Complete audit event and policy type definitions
//! - Serialization support (JSON via Serde)
//! - Audit level comparison and ordering
//! - API installation utilities
//!
//! ## Quick Start
//!
//! ```rust
//! use k8s_audit_apis::audit;
//!
//! // Create an audit event
//! let event = audit::Event {
//!     audit_id: "test-id".into(),
//!     request_uri: "/api/v1/pods".to_string(),
//!     verb: "list".to_string(),
//!     level: audit::Level::Metadata,
//!     stage: audit::Stage::RequestReceived,
//!     ..Default::default()
//! };
//!
//! // Compare audit levels
//! assert!(audit::Level::Metadata < audit::Level::Request);
//! ```
//!
//! ## Module Structure
//!
//! - [`audit`] - Main audit module containing all types and utilities
//!   - [`Level`] - Audit logging levels (None, Metadata, Request, RequestResponse)
//!   - [`Stage`] - Request handling stages
//!   - [`Event`] - Complete audit event
//!   - [`Policy`] - Audit policy configuration
//!   - [`PolicyRule`] - Individual policy rules
//!
//! ## Cargo Features
//!
//! - `serde` - Enables JSON serialization (enabled by default)
//! - `v1` - v1 API version support (not yet implemented)
//! - `validation` - Policy validation (not yet implemented)

// 开发阶段先放宽检查，生产时应该添加完整文档
#![allow(missing_docs)]
#![warn(rust_2018_idioms)]
#![warn(missing_debug_implementations)]

/// Main audit module
pub mod audit;

// Re-export for convenience
pub use audit::*;
