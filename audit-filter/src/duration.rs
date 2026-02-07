/*
版权所有 Kubernetes 作者。

根据 Apache 许可证 2.0 版（"许可证"）获得许可；
除非符合许可证，否则不得使用此文件。
您可以在以下网址获取许可证副本：

    http://www.apache.org/licenses/LICENSE-2.0

除非适用法律要求或书面同意，否则根据许可证分发的软件
按"原样"分发，无任何明示或暗示的担保或条件。
请参阅许可证了解特定语言的权限和限制。
*/

use chrono::TimeDelta;
use std::fmt;

/// ShortHumanDuration 返回一个简洁的持续时间表示
/// 精度有限，供人类使用。
pub fn short_human_duration(d: TimeDelta) -> String {
    // 允许不超过2秒（不包括）的偏差以容忍机器时间不一致，
    // 可以将其视为几乎是现在。
    let seconds = d.num_seconds();
    
    if seconds < -1 {
        return "<invalid>".to_string();
    } else if seconds < 0 {
        return "0s".to_string();
    } else if seconds < 60 {
        return format!("{}s", seconds);
    } else {
        let minutes = d.num_minutes();
        if minutes < 60 {
            return format!("{}m", minutes);
        } else {
            let hours = d.num_hours();
            if hours < 24 {
                return format!("{}h", hours);
            } else if hours < 24 * 365 {
                return format!("{}d", hours / 24);
            }
            return format!("{}y", hours / 24 / 365);
        }
    }
}

/// HumanDuration 返回一个简洁的持续时间表示
/// 精度有限，供人类使用。它提供约2-3位有效数字的持续时间。
pub fn human_duration(d: TimeDelta) -> String {
    // 允许不超过2秒（不包括）的偏差以容忍机器时间不一致，
    // 可以将其视为几乎是现在。
    let seconds = d.num_seconds();
    
    if seconds < -1 {
        return "<invalid>".to_string();
    } else if seconds < 0 {
        return "0s".to_string();
    } else if seconds < 60 * 2 {
        return format!("{}s", seconds);
    }
    
    let minutes = d.num_minutes();
    if minutes < 10 {
        let s = d.num_seconds() % 60;
        if s == 0 {
            return format!("{}m", minutes);
        }
        return format!("{}m{}s", minutes, s);
    } else if minutes < 60 * 3 {
        return format!("{}m", minutes);
    }
    
    let hours = d.num_hours();
    if hours < 8 {
        let m = d.num_minutes() % 60;
        if m == 0 {
            return format!("{}h", hours);
        }
        return format!("{}h{}m", hours, m);
    } else if hours < 48 {
        return format!("{}h", hours);
    } else if hours < 24 * 8 {
        let h = hours % 24;
        if h == 0 {
            return format!("{}d", hours / 24);
        }
        return format!("{}d{}h", hours / 24, h);
    } else if hours < 24 * 365 * 2 {
        return format!("{}d", hours / 24);
    } else if hours < 24 * 365 * 8 {
        let dy = (hours / 24) % 365;
        if dy == 0 {
            return format!("{}y", hours / 24 / 365);
        }
        return format!("{}y{}d", hours / 24 / 365, dy);
    }
    
    return format!("{}y", hours / 24 / 365);
}

/// 为 TimeDelta 添加扩展方法，提供更友好的 API
pub trait DurationExt {
    /// 返回简洁的持续时间表示（短格式）
    fn short_human_duration(&self) -> String;
    
    /// 返回简洁的持续时间表示（详细格式，约2-3位有效数字）
    fn human_duration(&self) -> String;
}

impl DurationExt for TimeDelta {
    fn short_human_duration(&self) -> String {
        short_human_duration(*self)
    }
    
    fn human_duration(&self) -> String {
        human_duration(*self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeDelta;
    
    #[test]
    fn test_short_human_duration() {
        // 测试无效值
        assert_eq!(short_human_duration(TimeDelta::seconds(-2)), "<invalid>");
        assert_eq!(short_human_duration(TimeDelta::seconds(-1)), "0s");
        assert_eq!(short_human_duration(TimeDelta::seconds(0)), "0s");
        
        // 测试秒
        assert_eq!(short_human_duration(TimeDelta::seconds(30)), "30s");
        assert_eq!(short_human_duration(TimeDelta::seconds(59)), "59s");
        
        // 测试分钟
        assert_eq!(short_human_duration(TimeDelta::seconds(60)), "1m");
        assert_eq!(short_human_duration(TimeDelta::minutes(30)), "30m");
        assert_eq!(short_human_duration(TimeDelta::minutes(59)), "59m");
        
        // 测试小时
        assert_eq!(short_human_duration(TimeDelta::minutes(60)), "1h");
        assert_eq!(short_human_duration(TimeDelta::hours(5)), "5h");
        assert_eq!(short_human_duration(TimeDelta::hours(23)), "23h");
        
        // 测试天
        assert_eq!(short_human_duration(TimeDelta::hours(24)), "1d");
        assert_eq!(short_human_duration(TimeDelta::days(3)), "3d");
        assert_eq!(short_human_duration(TimeDelta::days(364)), "364d");
        
        // 测试年
        assert_eq!(short_human_duration(TimeDelta::days(365)), "1y");
        assert_eq!(short_human_duration(TimeDelta::days(730)), "2y");
        assert_eq!(short_human_duration(TimeDelta::days(1000)), "2y"); // 1000/365=2.74 向下取整
    }
    
    #[test]
    fn test_human_duration() {
        // 测试无效值
        assert_eq!(human_duration(TimeDelta::seconds(-2)), "<invalid>");
        assert_eq!(human_duration(TimeDelta::seconds(-1)), "0s");
        assert_eq!(human_duration(TimeDelta::seconds(0)), "0s");
        
        // 测试 2 分钟内的秒
        assert_eq!(human_duration(TimeDelta::seconds(30)), "30s");
        assert_eq!(human_duration(TimeDelta::seconds(119)), "119s"); // 1分59秒，但小于2分钟
        
        // 测试分钟（小于10分钟，显示秒）
        assert_eq!(human_duration(TimeDelta::seconds(120)), "2m"); // 正好2分钟
        assert_eq!(human_duration(TimeDelta::seconds(121)), "2m1s"); // 2分1秒
        assert_eq!(human_duration(TimeDelta::minutes(5)), "5m");
        assert_eq!(human_duration(TimeDelta::minutes(5) + TimeDelta::seconds(30)), "5m30s");
        assert_eq!(human_duration(TimeDelta::minutes(9) + TimeDelta::seconds(59)), "9m59s");
        
        // 测试分钟（10分钟到3小时）
        assert_eq!(human_duration(TimeDelta::minutes(10)), "10m");
        assert_eq!(human_duration(TimeDelta::minutes(30)), "30m");
        assert_eq!(human_duration(TimeDelta::minutes(179)), "179m"); // 2小时59分，但小于3小时
        
        // 测试小时（小于8小时，显示分钟）
        assert_eq!(human_duration(TimeDelta::minutes(180)), "3h"); // 正好3小时
        assert_eq!(human_duration(TimeDelta::hours(3) + TimeDelta::minutes(5)), "3h5m");
        assert_eq!(human_duration(TimeDelta::hours(7) + TimeDelta::minutes(59)), "7h59m");
        
        // 测试小时（8到48小时）
        assert_eq!(human_duration(TimeDelta::hours(8)), "8h");
        assert_eq!(human_duration(TimeDelta::hours(30)), "30h");
        assert_eq!(human_duration(TimeDelta::hours(47)), "47h");
        
        // 测试天（小于8天，显示小时）
        assert_eq!(human_duration(TimeDelta::hours(48)), "2d"); // 正好2天
        assert_eq!(human_duration(TimeDelta::days(2) + TimeDelta::hours(5)), "2d5h");
        assert_eq!(human_duration(TimeDelta::days(7) + TimeDelta::hours(23)), "7d23h");
        
        // 测试天（8天到2年）
        assert_eq!(human_duration(TimeDelta::days(8)), "8d");
        assert_eq!(human_duration(TimeDelta::days(100)), "100d");
        assert_eq!(human_duration(TimeDelta::days(729)), "729d"); // 刚好小于2年
        
        // 测试年（2到8年，显示天）
        assert_eq!(human_duration(TimeDelta::days(730)), "2y"); // 正好2年
        assert_eq!(human_duration(TimeDelta::days(730) + TimeDelta::days(100)), "2y100d");
        assert_eq!(human_duration(TimeDelta::days(365 * 7) + TimeDelta::days(300)), "7y300d");
        
        // 测试年（8年以上）
        assert_eq!(human_duration(TimeDelta::days(365 * 8)), "8y");
        assert_eq!(human_duration(TimeDelta::days(365 * 10)), "10y");
    }
    
    #[test]
    fn test_duration_ext() {
        let delta = TimeDelta::hours(3) + TimeDelta::minutes(30);
        
        // 测试扩展方法
        assert_eq!(delta.short_human_duration(), "3h");
        assert_eq!(delta.human_duration(), "3h30m");
        
        // 测试不同时间长度
        assert_eq!(TimeDelta::seconds(45).short_human_duration(), "45s");
        assert_eq!(TimeDelta::seconds(45).human_duration(), "45s");
        
        assert_eq!(TimeDelta::days(400).short_human_duration(), "1y");
        assert_eq!(TimeDelta::days(400).human_duration(), "1y35d");
    }
    
    #[test]
    fn test_edge_cases() {
        // 边界情况测试
        assert_eq!(human_duration(TimeDelta::seconds(119)), "119s"); // 小于2分钟
        assert_eq!(human_duration(TimeDelta::seconds(120)), "2m");   // 正好2分钟
        
        assert_eq!(human_duration(TimeDelta::minutes(9) + TimeDelta::seconds(59)), "9m59s");
        assert_eq!(human_duration(TimeDelta::minutes(10)), "10m");   // 正好10分钟
        
        assert_eq!(human_duration(TimeDelta::minutes(179)), "179m"); // 小于3小时
        assert_eq!(human_duration(TimeDelta::minutes(180)), "3h");   // 正好3小时
        
        assert_eq!(human_duration(TimeDelta::hours(7) + TimeDelta::minutes(59)), "7h59m");
        assert_eq!(human_duration(TimeDelta::hours(8)), "8h");       // 正好8小时
        
        assert_eq!(human_duration(TimeDelta::hours(47)), "47h");     // 小于2天
        assert_eq!(human_duration(TimeDelta::hours(48)), "2d");      // 正好2天
        
        assert_eq!(human_duration(TimeDelta::days(7) + TimeDelta::hours(23)), "7d23h");
        assert_eq!(human_duration(TimeDelta::days(8)), "8d");        // 正好8天
        
        assert_eq!(human_duration(TimeDelta::days(729)), "729d");    // 小于2年
        assert_eq!(human_duration(TimeDelta::days(730)), "2y");      // 正好2年
        
        assert_eq!(human_duration(TimeDelta::days(365 * 7) + TimeDelta::days(364)), "7y364d");
        assert_eq!(human_duration(TimeDelta::days(365 * 8)), "8y");  // 正好8年
    }
}

// 示例使用
fn main() {
    use chrono::TimeDelta;
    
    println!("=== Kubernetes Duration 示例 ===");
    
    // 测试不同时间长度的格式化
    let test_durations = vec![
        ("30秒", TimeDelta::seconds(30)),
        ("2分钟", TimeDelta::minutes(2)),
        ("2分30秒", TimeDelta::minutes(2) + TimeDelta::seconds(30)),
        ("5分钟", TimeDelta::minutes(5)),
        ("5分30秒", TimeDelta::minutes(5) + TimeDelta::seconds(30)),
        ("3小时", TimeDelta::hours(3)),
        ("3小时15分", TimeDelta::hours(3) + TimeDelta::minutes(15)),
        ("10小时", TimeDelta::hours(10)),
        ("2天", TimeDelta::days(2)),
        ("2天5小时", TimeDelta::days(2) + TimeDelta::hours(5)),
        ("10天", TimeDelta::days(10)),
        ("1年", TimeDelta::days(365)),
        ("1年100天", TimeDelta::days(365 + 100)),
        ("5年", TimeDelta::days(365 * 5)),
        ("10年", TimeDelta::days(365 * 10)),
    ];
    
    for (desc, duration) in test_durations {
        println!("{}:", desc);
        println!("  短格式: {}", duration.short_human_duration());
        println!("  详细格式: {}", duration.human_duration());
        println!();
    }
    
    // 模拟 Kubernetes 中显示资源年龄
    println!("=== 模拟 Kubernetes 资源年龄显示 ===");
    
    let resource_ages = vec![
        ("新创建的 Pod", TimeDelta::seconds(30)),
        ("运行中的服务", TimeDelta::hours(3)),
        ("部署的应用", TimeDelta::days(2)),
        ("长期运行的系统", TimeDelta::days(400)),
        ("遗留系统", TimeDelta::days(365 * 3)),
    ];
    
    for (desc, age) in resource_ages {
        println!("{}: {}", desc, age.human_duration());
    }
}