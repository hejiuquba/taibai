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

//! 审计辅助函数
//!
//! 此模块包含审计级别的比较和排序函数。

use crate::audit;

/// 获取审计级别的序号
///
/// # 参数
/// * `level` - 审计级别
///
/// # 返回值
/// 级别的序号，用于比较和排序
pub fn ord_level(level: &audit::Level) -> u8 {
    match level {
        audit::Level::None => 0,
        audit::Level::Metadata => 1,
        audit::Level::Request => 2,
        audit::Level::RequestResponse => 3,
    }
}

/// Level 类型的扩展方法
pub trait LevelExt {
    /// 检查当前级别是否小于另一个级别
    ///
    /// # 参数
    /// * `other` - 要比较的另一个级别
    ///
    /// # 返回值
    /// 如果当前级别小于另一个级别则返回 true
    fn less(&self, other: &Self) -> bool;

    /// 检查当前级别是否大于或等于另一个级别
    ///
    /// # 参数
    /// * `other` - 要比较的另一个级别
    ///
    /// # 返回值
    /// 如果当前级别大于或等于另一个级别则返回 true
    fn greater_or_equal(&self, other: &Self) -> bool;

    /// 获取级别的序号
    ///
    /// # 返回值
    /// 级别的序号值
    fn ordinal(&self) -> u8;
}

impl LevelExt for audit::Level {
    fn less(&self, other: &Self) -> bool {
        ord_level(self) < ord_level(other)
    }

    fn greater_or_equal(&self, other: &Self) -> bool {
        ord_level(self) >= ord_level(other)
    }

    fn ordinal(&self) -> u8 {
        ord_level(self)
    }
}

/// 为 Level 实现 PartialOrd，使其支持比较操作符
impl std::cmp::PartialOrd for audit::Level {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// 为 Level 实现 Ord，使其完全可排序
impl std::cmp::Ord for audit::Level {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        ord_level(self).cmp(&ord_level(other))
    }
}

/// 为 Level 实现 PartialEq 和 Eq
/// 注意：Level 已经通过 #[derive(PartialEq, Eq)] 实现了这些 trait
/// 这里是为了确保一致性

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::Level;

    #[test]
    fn test_ord_level() {
        assert_eq!(ord_level(&Level::None), 0);
        assert_eq!(ord_level(&Level::Metadata), 1);
        assert_eq!(ord_level(&Level::Request), 2);
        assert_eq!(ord_level(&Level::RequestResponse), 3);
    }

    #[test]
    fn test_level_less() {
        assert!(Level::None.less(&Level::Metadata));
        assert!(Level::Metadata.less(&Level::Request));
        assert!(Level::Request.less(&Level::RequestResponse));

        assert!(!Level::Metadata.less(&Level::None));
        assert!(!Level::RequestResponse.less(&Level::Request));
    }

    #[test]
    fn test_level_greater_or_equal() {
        assert!(Level::Metadata.greater_or_equal(&Level::None));
        assert!(Level::Request.greater_or_equal(&Level::Metadata));
        assert!(Level::RequestResponse.greater_or_equal(&Level::Request));

        assert!(Level::None.greater_or_equal(&Level::None));
        assert!(Level::Metadata.greater_or_equal(&Level::Metadata));

        assert!(!Level::None.greater_or_equal(&Level::Metadata));
        assert!(!Level::Metadata.greater_or_equal(&Level::Request));
    }

    #[test]
    fn test_level_ordinal() {
        assert_eq!(Level::None.ordinal(), 0);
        assert_eq!(Level::Metadata.ordinal(), 1);
        assert_eq!(Level::Request.ordinal(), 2);
        assert_eq!(Level::RequestResponse.ordinal(), 3);
    }

    #[test]
    fn test_comparison_operators() {
        use std::cmp::Ordering;

        // 测试比较操作符
        assert_eq!(Level::None.cmp(&Level::Metadata), Ordering::Less);
        assert_eq!(Level::Metadata.cmp(&Level::None), Ordering::Greater);
        assert_eq!(Level::Metadata.cmp(&Level::Metadata), Ordering::Equal);

        // 测试 PartialOrd 的操作符
        assert!(Level::None < Level::Metadata);
        assert!(Level::Metadata <= Level::Request);
        assert!(Level::RequestResponse > Level::Request);
        assert!(Level::RequestResponse >= Level::RequestResponse);
    }

    #[test]
    fn test_level_ordering() {
        let mut levels = vec![
            Level::Request,
            Level::None,
            Level::RequestResponse,
            Level::Metadata,
        ];

        // 排序
        levels.sort();

        // 验证排序顺序
        assert_eq!(levels[0], Level::None);
        assert_eq!(levels[1], Level::Metadata);
        assert_eq!(levels[2], Level::Request);
        assert_eq!(levels[3], Level::RequestResponse);
    }
}
