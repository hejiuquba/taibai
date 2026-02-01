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
limitations under the above.
*/

// 核心模块
mod helpers;
mod types;

// 条件编译模块
#[cfg(feature = "validation")]
pub mod validation;

#[cfg(feature = "v1")]
pub mod v1;

// 导出核心类型
pub use helpers::*;
pub use types::*;

// 条件导出
#[cfg(feature = "validation")]
pub use validation::*;

/// API 组名常量
pub const GROUP_NAME: &str = "audit.k8s.io";

/// 初始化审计系统
pub fn init() -> Result<(), Box<dyn std::error::Error>> {
    // 删除 v1 安装初始化
    // #[cfg(feature = "v1")]
    // install::init()?;  // 删除这一行

    Ok(())
}
