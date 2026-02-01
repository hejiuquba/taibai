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

//! 审计策略模块
//!
//! 此模块提供了审计策略的读取、检查和评估功能。

pub mod checker;
pub mod reader;
pub mod util;

// 重新导出
pub use checker::{new_policy_rule_evaluator, new_fake_policy_rule_evaluator, DEFAULT_AUDIT_LEVEL};
pub use reader::{load_policy_from_file, load_policy_from_bytes, PolicyReaderError};
pub use util::{all_stages, all_levels, invert_stages, merge_stages};