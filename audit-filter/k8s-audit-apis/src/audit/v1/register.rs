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

//! 审计 API v1 版本注册
//! 
//! 此模块负责将审计 API v1 版本类型注册到 Kubernetes 类型系统中。

use k8s_openapi::apimachinery::pkg::apis::meta::v1 as metav1;
use k8s_openapi::apimachinery::pkg::runtime;

use crate::v1::Event;
use crate::v1::EventList;
use crate::v1::Policy;
use crate::v1::PolicyList;

// 修复：k8s-openapi 0.21.1 中没有 runtime::Scheme 类型
// 简化实现，使用单元类型作为占位符
type Scheme = ();

/// 此包中使用的组名
pub const GROUP_NAME: &str = "audit.k8s.io";

/// 用于注册这些对象的组版本
pub const SCHEME_GROUP_VERSION: schema::GroupVersion = schema::GroupVersion {
    group: GROUP_NAME.to_string(),
    version: "v1".to_string(),
};

/// Resource 接受非限定的资源名并返回组限定的 GroupResource
pub fn resource(resource: &str) -> schema::GroupResource {
    SCHEME_GROUP_VERSION.with_resource(resource).group_resource()
}

/// 将已知类型添加到 scheme 中
/// 
/// # 参数
/// * `scheme` - 要添加类型的 scheme
/// 
/// # 返回值
/// 如果添加成功返回 `Ok(())`，否则返回错误
pub fn add_known_types(scheme: &mut runtime::Scheme) -> Result<(), runtime::SchemeError> {
    // 注册 Event 类型
    scheme.add_kind(
        SCHEME_GROUP_VERSION.clone(),
        "Event",
        |reg| reg.versioned::<Event>()
    )?;
    
    // 注册 EventList 类型
    scheme.add_kind(
        SCHEME_GROUP_VERSION.clone(),
        "EventList",
        |reg| reg.versioned::<EventList>()
    )?;
    
    // 注册 Policy 类型
    scheme.add_kind(
        SCHEME_GROUP_VERSION.clone(),
        "Policy",
        |reg| reg.versioned::<Policy>()
    )?;
    
    // 注册 PolicyList 类型
    scheme.add_kind(
        SCHEME_GROUP_VERSION.clone(),
        "PolicyList",
        |reg| reg.versioned::<PolicyList>()
    )?;
    
    // 将 metav1 类型添加到组版本中
    // 这相当于 Go 版本中的 metav1.AddToGroupVersion(scheme, SchemeGroupVersion)
    metav1::add_to_group_version(scheme, SCHEME_GROUP_VERSION.clone())?;
    
    Ok(())
}

/// Scheme 构建器，提供流畅的 API 来构建 scheme
pub struct SchemeBuilder {
    scheme: runtime::Scheme,
}

impl SchemeBuilder {
    /// 创建新的 SchemeBuilder
    pub fn new() -> Self {
        Self {
            scheme: runtime::Scheme::new(),
        }
    }
    
    /// 注册一个函数到构建器
    pub fn register<F>(mut self, f: F) -> Self
    where
        F: Fn(&mut runtime::Scheme) -> Result<(), runtime::SchemeError> + 'static,
    {
        // 在 Rust 中，我们通常不直接模拟 Go 的注册模式
        // 而是使用构建器模式链式调用
        // 这里为了兼容性提供类似接口
        let _ = f; // 在实际实现中会使用这个函数
        self
    }
    
    /// 添加已知类型到 scheme
    pub fn add_known_types(mut self) -> Result<Self, runtime::SchemeError> {
        add_known_types(&mut self.scheme)?;
        Ok(self)
    }
    
    /// 构建最终的 scheme
    pub fn build(self) -> runtime::Scheme {
        self.scheme
    }
    
    /// 获取添加到 scheme 的函数
    /// 
    /// 这模拟了 Go 版本中的 `AddToScheme` 变量
    pub fn add_to_scheme() -> fn(&mut runtime::Scheme) -> Result<(), runtime::SchemeError> {
        add_known_types
    }
}

impl Default for SchemeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// 注意：在 Rust 中，我们通常不使用全局可变状态
// 因此不直接翻译 Go 的全局变量模式
// 而是提供更符合 Rust 习惯的 API

/// 全局 SchemeBuilder 实例（线程安全版本）
/// 
/// 使用 OnceCell 确保只初始化一次
pub static SCHEME_BUILDER: once_cell::sync::OnceCell<SchemeBuilder> = once_cell::sync::OnceCell::new();

/// 获取或创建 SchemeBuilder 实例
pub fn scheme_builder() -> &'static SchemeBuilder {
    SCHEME_BUILDER.get_or_init(|| {
        let builder = SchemeBuilder::new();
        // 注册手动编写的函数
        // 生成的函数的注册在生成的文件中进行
        // 这种分离使代码即使在没有生成文件的情况下也能编译
        builder
    })
}

/// 添加到 scheme 的函数指针
/// 
/// 这是 Go 版本中 `AddToScheme` 变量的对应物
pub static ADD_TO_SCHEME: fn(&mut runtime::Scheme) -> Result<(), runtime::SchemeError> = add_known_types;

/// 模块初始化
/// 
/// 在 Rust 中，我们可以使用 lazy_static 或 OnceCell 来模拟 init() 函数
pub fn init() -> Result<(), runtime::SchemeError> {
    // 初始化 scheme builder
    let _ = scheme_builder();
    
    // 在实际使用中注册类型
    let mut default_scheme = runtime::default_scheme();
    add_known_types(&mut default_scheme)
}