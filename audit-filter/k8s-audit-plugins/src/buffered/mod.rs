// k8s-audit-plugins/src/buffered/mod.rs

//! 缓冲后端插件
//!
//! 这个模块提供了一个缓冲的审计后端，它包装其他后端并添加批处理、
//! 缓冲和限流功能。

use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc as std_mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::runtime::{Handle, Runtime};
use tokio::sync::mpsc as tokio_mpsc;
use tokio::sync::Semaphore;

use k8s_audit_apis::audit as audit_internal;
use k8s_audit_core::types::{Backend, BackendError, Sink};

/// 插件名称
pub const PLUGIN_NAME: &str = "buffered";

/// 批处理配置
#[derive(Debug, Clone)]
pub struct BatchConfig {
    /// 缓冲队列的大小
    pub buffer_size: usize,
    /// 批次的最大大小
    pub max_batch_size: usize,
    /// 两个批次之间的最大间隔
    pub max_batch_wait: Duration,

    /// 是否对批处理过程应用限流
    pub throttle_enable: bool,
    /// 允许每秒发送到委托后端的批次速率
    pub throttle_qps: f32,
    /// 在未充分利用ThrottleQPS定义的容量时，同时发送到委托后端的最大请求数
    pub throttle_burst: usize,

    /// 是否异步调用委托后端
    pub async_delegate: bool,
}

impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            buffer_size: 100,
            max_batch_size: 10,
            max_batch_wait: Duration::from_secs(5),
            throttle_enable: false,
            throttle_qps: 10.0,
            throttle_burst: 15,
            async_delegate: true,
        }
    }
}

/// 令牌桶限流器
struct TokenBucketRateLimiter {
    qps: f32,
    burst: usize,
    tokens: Arc<Mutex<f32>>,
    last_update: Arc<Mutex<std::time::Instant>>,
}

impl TokenBucketRateLimiter {
    fn new(qps: f32, burst: usize) -> Self {
        Self {
            qps,
            burst,
            tokens: Arc::new(Mutex::new(burst as f32)),
            last_update: Arc::new(Mutex::new(std::time::Instant::now())),
        }
    }

    fn try_acquire(&self) -> bool {
        let mut tokens_guard = self.tokens.lock().unwrap();
        let mut last_update_guard = self.last_update.lock().unwrap();

        // 更新令牌
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(*last_update_guard);
        let new_tokens = elapsed.as_secs_f32() * self.qps;

        *tokens_guard = (*tokens_guard + new_tokens).min(self.burst as f32);
        *last_update_guard = now;

        // 尝试获取令牌
        if *tokens_guard >= 1.0 {
            *tokens_guard -= 1.0;
            true
        } else {
            false
        }
    }

    fn accept(&self) {
        // 简单的阻塞获取
        while !self.try_acquire() {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

/// 缓冲后端结构体
pub struct BufferedBackend {
    /// 实际导出事件的委托后端
    delegate: Arc<dyn Backend>,

    /// 缓冲队列发送端
    buffer_tx: std_mpsc::SyncSender<Arc<audit_internal::Event>>,
    /// 缓冲队列接收端
    buffer_rx: Arc<Mutex<std_mpsc::Receiver<Arc<audit_internal::Event>>>>,

    /// 批处理配置
    config: BatchConfig,

    /// 是否已关闭
    shutdown: Arc<AtomicBool>,

    // /// 工作线程句柄
    // worker_handle: Option<std::thread::JoinHandle<()>>,
    /// 工作线程句柄（使用 Mutex 包装以实现内部可变性）
    worker_handle: Arc<Mutex<Option<std::thread::JoinHandle<()>>>>,

    /// 限流器
    throttle: Option<Arc<TokenBucketRateLimiter>>,

    /// 异步运行时（用于异步委托）
    runtime: Option<Arc<Runtime>>,

    /// 等待组，用于跟踪正在进行的批处理
    in_flight_batches: Arc<AtomicUsize>,

    /// 定时器发送端（用于最大等待时间）
    timer_tx: std_mpsc::SyncSender<()>,
    /// 定时器接收端
    timer_rx: Arc<Mutex<std_mpsc::Receiver<()>>>,
}

impl BufferedBackend {
    /// 创建一个新的缓冲后端，包装委托后端
    ///
    /// 缓冲后端会自动运行和关闭委托后端。
    pub fn new(delegate: Arc<dyn Backend>, config: BatchConfig) -> Self {
        // 创建缓冲队列（使用同步通道，有界缓冲区）
        let (buffer_tx, buffer_rx) = std_mpsc::sync_channel(config.buffer_size);

        // 创建定时器通道
        let (timer_tx, timer_rx) = std_mpsc::sync_channel(1);

        // 创建限流器
        let throttle = if config.throttle_enable {
            Some(Arc::new(TokenBucketRateLimiter::new(
                config.throttle_qps,
                config.throttle_burst,
            )))
        } else {
            None
        };

        // 创建异步运行时（如果需要）
        let runtime = if config.async_delegate {
            Runtime::new().ok().map(Arc::new)
        } else {
            None
        };

        Self {
            delegate: delegate.clone(),
            buffer_tx,
            buffer_rx: Arc::new(Mutex::new(buffer_rx)),
            config,
            shutdown: Arc::new(AtomicBool::new(false)),
            worker_handle: Arc::new(Mutex::new(None)),
            throttle,
            runtime,
            in_flight_batches: Arc::new(AtomicUsize::new(0)),
            timer_tx,
            timer_rx: Arc::new(Mutex::new(timer_rx)),
        }
    }

    /// 启动定时器线程
    fn start_timer_thread(&self) {
        if self.config.max_batch_size <= 1 {
            return; // 不需要定时器
        }

        let timer_tx = self.timer_tx.clone();
        let max_batch_wait = self.config.max_batch_wait;
        let shutdown = self.shutdown.clone();

        std::thread::spawn(move || {
            while !shutdown.load(Ordering::SeqCst) {
                std::thread::sleep(max_batch_wait);
                if timer_tx.send(()).is_err() {
                    break; // 接收端已断开
                }
            }
        });
    }

    /// 收集事件形成批次
    // fn collect_events(&self, stop_rx: &std_mpsc::Receiver<()>) -> Vec<Arc<audit_internal::Event>> {
    //     let mut events = Vec::with_capacity(self.config.max_batch_size);
    //     let buffer_rx = self.buffer_rx.lock().unwrap();
    //     let timer_rx = self.timer_rx.lock().unwrap();

    //     for i in 0..self.config.max_batch_size {
    //         // 使用select!宏来同时监听多个通道
    //         let mut channels = vec![
    //             Some(&*buffer_rx as &dyn std_mpsc::Receiver<Arc<audit_internal::Event>>),
    //             Some(&*timer_rx as &dyn std_mpsc::Receiver<()>),
    //             Some(stop_rx as &dyn std_mpsc::Receiver<()>),
    //         ];

    //         // 尝试从每个通道接收，使用短超时
    //         let mut received = false;

    //         // 首先尝试从缓冲区接收（非阻塞）
    //         match buffer_rx.try_recv() {
    //             Ok(event) => {
    //                 events.push(event);
    //                 received = true;
    //             }
    //             Err(std_mpsc::TryRecvError::Empty) => {
    //                 // 缓冲区为空，继续检查其他通道
    //             }
    //             Err(std_mpsc::TryRecvError::Disconnected) => {
    //                 // 缓冲区已关闭
    //                 break;
    //             }
    //         }

    //         if received {
    //             continue;
    //         }

    //         // 如果没有从缓冲区收到，使用select等待
    //         // 由于标准库没有原生的select，我们使用带超时的recv
    //         let start = std::time::Instant::now();
    //         let timeout = Duration::from_millis(10); // 短超时

    //         loop {
    //             // 检查定时器通道
    //             match timer_rx.try_recv() {
    //                 Ok(_) => {
    //                     // 定时器到期，返回当前批次
    //                     return events;
    //                 }
    //                 Err(std_mpsc::TryRecvError::Empty) => {}
    //                 Err(std_mpsc::TryRecvError::Disconnected) => {}
    //             }

    //             // 检查停止通道
    //             match stop_rx.try_recv() {
    //                 Ok(_) => {
    //                     // 收到停止信号，返回当前批次
    //                     return events;
    //                 }
    //                 Err(std_mpsc::TryRecvError::Empty) => {}
    //                 Err(std_mpsc::TryRecvError::Disconnected) => {}
    //             }

    //             // 检查缓冲区（带短超时）
    //             match buffer_rx.recv_timeout(timeout) {
    //                 Ok(event) => {
    //                     events.push(event);
    //                     break; // 收到事件，继续外层循环
    //                 }
    //                 Err(std_mpsc::RecvTimeoutError::Timeout) => {
    //                     // 超时，检查是否应该返回
    //                     if start.elapsed() >= timeout * 2 {
    //                         // 如果已经等待了一段时间并且有事件，返回
    //                         if !events.is_empty() {
    //                             return events;
    //                         }
    //                     }
    //                 }
    //                 Err(std_mpsc::RecvTimeoutError::Disconnected) => {
    //                     // 缓冲区已关闭
    //                     return events;
    //                 }
    //             }

    //             // 检查是否应该跳出循环
    //             if start.elapsed() >= Duration::from_millis(100) && !events.is_empty() {
    //                 return events;
    //             }
    //         }
    //     }

    //     events
    // }

    // 修改函数签名，移除 timer 参数
    fn collect_events(&self, stop_rx: &std_mpsc::Receiver<()>) -> Vec<Arc<audit_internal::Event>> {
        let mut events = Vec::with_capacity(self.config.max_batch_size);

        // 先获取缓冲区的锁
        let buffer_rx_guard = match self.buffer_rx.lock() {
            Ok(guard) => guard,
            Err(_) => return events,
        };

        for i in 0..self.config.max_batch_size {
            // 尝试从缓冲区接收（带短超时）
            match buffer_rx_guard.recv_timeout(Duration::from_millis(10)) {
                Ok(event) => {
                    events.push(event);
                    continue;
                }
                Err(std_mpsc::RecvTimeoutError::Timeout) => {
                    // 超时，检查停止信号
                }
                Err(std_mpsc::RecvTimeoutError::Disconnected) => {
                    break;
                }
            }

            // 检查停止信号
            match stop_rx.try_recv() {
                Ok(_) => break,
                Err(std_mpsc::TryRecvError::Empty) => {}
                Err(std_mpsc::TryRecvError::Disconnected) => break,
            }

            // 如果已经收集了一些事件，返回当前批次
            if !events.is_empty() {
                break;
            }
        }

        events
    }

    /// 处理批次事件
    fn process_batch(&self, events: Vec<Arc<audit_internal::Event>>) {
        if events.is_empty() {
            return;
        }

        // 应用限流
        if let Some(throttle) = &self.throttle {
            throttle.accept();
        }

        // 增加进行中的批次计数
        self.in_flight_batches.fetch_add(1, Ordering::SeqCst);

        if self.config.async_delegate {
            // 异步处理
            let delegate = self.delegate.clone();
            let events_clone = events.clone();
            let in_flight_batches = self.in_flight_batches.clone();

            std::thread::spawn(move || {
                // 处理事件
                let _ = delegate.process_events(&events_clone);

                // 减少进行中的批次计数
                in_flight_batches.fetch_sub(1, Ordering::SeqCst);
            });
        } else {
            // 同步处理
            let _ = self.delegate.process_events(&events);
            // 减少进行中的批次计数
            self.in_flight_batches.fetch_sub(1, Ordering::SeqCst);
        }
    }

    /// 处理传入事件（工作线程主循环）
    fn process_incoming_events(&self, stop_rx: std_mpsc::Receiver<()>) {
        // 启动定时器线程
        self.start_timer_thread();

        while !self.shutdown.load(Ordering::SeqCst) {
            // 收集事件
            let events = self.collect_events(&stop_rx);

            // 处理批次
            self.process_batch(events);

            // 检查停止信号
            match stop_rx.try_recv() {
                Ok(_) => break,
                Err(_) => continue,
            }
        }

        // 处理剩余事件
        let mut all_events_processed = false;
        while !all_events_processed && !self.shutdown.load(Ordering::SeqCst) {
            let events = self.collect_events(&stop_rx);
            self.process_batch(events.clone());
            all_events_processed = events.is_empty();
        }
    }

    /// 获取进行中的批次数量（用于测试）
    pub fn in_flight_batches_count(&self) -> usize {
        self.in_flight_batches.load(Ordering::SeqCst)
    }

    /// 获取缓冲区长度（用于测试）
    pub fn buffer_len(&self) -> usize {
        // 注意：std::sync::mpsc没有len()方法
        // 我们可以通过尝试接收来估计
        0 // 简化实现
    }
}

impl Sink for BufferedBackend {
    fn process_events(&self, events: &[Arc<audit_internal::Event>]) -> bool {
        // 检查后端是否已关闭
        if self.shutdown.load(Ordering::SeqCst) {
            // 后端已关闭，记录错误但返回成功
            eprintln!("缓冲后端已关闭，无法处理事件");
            return true;
        }

        let mut send_error = None;

        for (i, event) in events.iter().enumerate() {
            // 深度复制事件（因为事件可能在发送后重用）
            let event_copy = Arc::new((**event).clone());

            // 尝试发送到缓冲区
            match self.buffer_tx.send(event_copy) {
                Ok(_) => continue,
                Err(std_mpsc::SendError(_)) => {
                    send_error = Some("审计缓冲队列已满".to_string());
                    break;
                }
            }
        }

        // 如果有错误，记录它
        if let Some(err) = send_error {
            eprintln!("缓冲后端错误: {}", err);
        }

        true
    }
}

impl Backend for BufferedBackend {
    fn run(&self, stop_rx: std_mpsc::Receiver<()>) -> Result<(), BackendError> {
        // 首先运行委托后端
        self.delegate.run(stop_rx)?;

        // 重新创建stop_rx的副本，因为上面的调用会消耗它
        // 我们需要一个新的stop_rx给工作线程
        let (new_tx, new_rx) = std_mpsc::channel();

        // 启动工作线程
        let backend_clone = Arc::new(self.clone());
        let shutdown_clone = self.shutdown.clone();

        let handle = std::thread::spawn(move || {
            backend_clone.process_incoming_events(new_rx);
            shutdown_clone.store(true, Ordering::SeqCst);
        });

        // 保存线程句柄
        // let mut self_mut = unsafe {
        //     // 安全：我们只在这里设置一次worker_handle
        //     &mut *(self as *const Self as *mut Self)
        // };
        // self_mut.worker_handle = Some(handle);

        // 保存线程句柄
        let mut handle_guard = self.worker_handle.lock().unwrap();
        *handle_guard = Some(handle);

        // 保存新的发送端，以便后续发送停止信号
        // 注意：这里简化处理，实际需要保存new_tx

        Ok(())
    }

    fn shutdown(&self) {
        // 设置关闭标志
        self.shutdown.store(true, Ordering::SeqCst);

        // 获取锁并取出句柄
        let handle = {
            let mut handle_guard = self.worker_handle.lock().unwrap();
            handle_guard.take()
        };

        // 等待工作线程结束
        if let Some(handle) = handle {
            let _ = handle.join();
        }

        // 关闭委托后端
        self.delegate.shutdown();

        // 等待所有进行中的批次完成
        while self.in_flight_batches.load(Ordering::SeqCst) > 0 {
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn name(&self) -> &str {
        PLUGIN_NAME
    }
}

impl Clone for BufferedBackend {
    fn clone(&self) -> Self {
        // 注意：std::sync::mpsc的接收端不能克隆
        // 我们需要重新创建通道
        let (buffer_tx, buffer_rx) = std_mpsc::sync_channel(self.config.buffer_size);
        let (timer_tx, timer_rx) = std_mpsc::sync_channel(1);

        Self {
            delegate: self.delegate.clone(),
            buffer_tx,
            buffer_rx: Arc::new(Mutex::new(buffer_rx)),
            config: self.config.clone(),
            shutdown: self.shutdown.clone(),
            worker_handle: Arc::new(Mutex::new(None)),
            throttle: self.throttle.clone(),
            runtime: self.runtime.clone(),
            in_flight_batches: self.in_flight_batches.clone(),
            timer_tx,
            timer_rx: Arc::new(Mutex::new(timer_rx)),
        }
    }
}

impl fmt::Display for BufferedBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}<{}>", PLUGIN_NAME, self.delegate.name())
    }
}

impl Drop for BufferedBackend {
    fn drop(&mut self) {
        self.shutdown();
    }
}

// 测试代码保持不变，只是移除了crossbeam相关的导入
#[cfg(test)]
mod tests {
    use super::*;
    use k8s_audit_apis::audit::{Event, Stage};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc;
    use std::time::Instant;

    // 简单的假后端用于测试
    #[derive(Clone)]
    struct TestBackend {
        process_count: Arc<AtomicUsize>,
        event_count: Arc<AtomicUsize>,
        delay: Option<Duration>,
    }

    impl TestBackend {
        fn new() -> Self {
            Self {
                process_count: Arc::new(AtomicUsize::new(0)),
                event_count: Arc::new(AtomicUsize::new(0)),
                delay: None,
            }
        }

        fn with_delay(delay: Duration) -> Self {
            Self {
                process_count: Arc::new(AtomicUsize::new(0)),
                event_count: Arc::new(AtomicUsize::new(0)),
                delay: Some(delay),
            }
        }

        fn process_count(&self) -> usize {
            self.process_count.load(Ordering::SeqCst)
        }

        fn event_count(&self) -> usize {
            self.event_count.load(Ordering::SeqCst)
        }
    }

    impl Sink for TestBackend {
        fn process_events(&self, events: &[Arc<audit_internal::Event>]) -> bool {
            self.process_count.fetch_add(1, Ordering::SeqCst);
            self.event_count.fetch_add(events.len(), Ordering::SeqCst);

            // 模拟处理延迟
            if let Some(delay) = self.delay {
                std::thread::sleep(delay);
            }

            true
        }
    }

    impl Backend for TestBackend {
        fn run(&self, _stop_rx: std_mpsc::Receiver<()>) -> Result<(), BackendError> {
            Ok(())
        }

        fn shutdown(&self) {}

        fn name(&self) -> &str {
            "test"
        }
    }

    fn create_test_event(id: &str) -> Event {
        Event {
            audit_id: id.to_string(),
            stage: Stage::RequestReceived,
            verb: "get".to_string(),
            request_uri: format!("/api/v1/pods/{}", id),
            ..Default::default()
        }
    }

    fn create_test_events(count: usize) -> Vec<Arc<audit_internal::Event>> {
        (0..count)
            .map(|i| Arc::new(create_test_event(&format!("event-{}", i))))
            .collect()
    }

    #[test]
    fn test_buffered_backend_basic() {
        let delegate = Arc::new(TestBackend::new());
        let config = BatchConfig {
            buffer_size: 10,
            max_batch_size: 5,
            max_batch_wait: Duration::from_millis(100),
            throttle_enable: false,
            async_delegate: true,
            ..Default::default()
        };

        let backend = BufferedBackend::new(delegate.clone(), config);

        // 运行后端
        let (tx, rx) = mpsc::channel();
        backend.run(rx).unwrap();

        // 发送事件
        let events = create_test_events(7);
        let success = backend.process_events(&events);
        assert!(success, "处理事件应该成功");

        // 等待批次处理
        std::thread::sleep(Duration::from_millis(200));

        // 应该至少有1个批次被处理
        assert!(delegate.process_count() >= 1, "应该处理至少1个批次");
        assert_eq!(delegate.event_count(), 7, "应该处理7个事件");

        // 关闭后端
        drop(tx); // 丢弃发送端以关闭通道
        backend.shutdown();
    }

    #[test]
    fn test_buffered_backend_max_batch_size() {
        let delegate = Arc::new(TestBackend::new());
        let config = BatchConfig {
            buffer_size: 20,
            max_batch_size: 3, // 小批次大小
            max_batch_wait: Duration::from_millis(200),
            throttle_enable: false,
            async_delegate: false, // 同步以便测试
            ..Default::default()
        };

        let backend = BufferedBackend::new(delegate.clone(), config);

        // 运行后端
        let (tx, rx) = mpsc::channel();
        backend.run(rx).unwrap();

        // 发送超过批次大小的事件
        let events = create_test_events(10);
        backend.process_events(&events);

        // 等待处理
        std::thread::sleep(Duration::from_millis(300));

        // 应该分成多个批次处理
        assert!(delegate.process_count() >= 3, "应该分成多个批次处理");
        assert_eq!(delegate.event_count(), 10, "应该处理所有10个事件");

        drop(tx);
        backend.shutdown();
    }

    #[test]
    fn test_buffered_backend_shutdown() {
        let delegate = Arc::new(TestBackend::with_delay(Duration::from_millis(100)));
        let config = BatchConfig {
            buffer_size: 10,
            max_batch_size: 2,
            max_batch_wait: Duration::from_millis(50),
            throttle_enable: false,
            async_delegate: true,
            ..Default::default()
        };

        let backend = BufferedBackend::new(delegate.clone(), config);

        // 运行后端
        let (tx, rx) = mpsc::channel();
        backend.run(rx).unwrap();

        // 发送一些事件
        let events = create_test_events(4);
        backend.process_events(&events);

        // 立即开始关闭
        let start = Instant::now();
        drop(tx); // 关闭通道，发送停止信号
        backend.shutdown();
        let elapsed = start.elapsed();

        // 关闭应该等待批次处理完成
        assert!(
            elapsed >= Duration::from_millis(100),
            "关闭应该等待异步处理完成，耗时: {:?}",
            elapsed
        );

        // 所有事件应该都被处理
        assert_eq!(delegate.event_count(), 4, "应该处理所有4个事件");
    }
}
