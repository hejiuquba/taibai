
K8s审计代码解析
2026年1月17日上午9点24分
分享
详细的解释一下k8s的audit的这段代码：// WithAudit decorates a http.Handler with audit logging information for all the
// requests coming to the server. Audit level is decided according to requests'
// attributes and audit policy. Logs are emitted to the audit sink to
// process events. If sink or audit policy is nil, no decoration takes place.
func WithAudit(handler http.Handler, sink audit.Sink, policy audit.PolicyRuleEvaluator, longRunningCheck request.LongRunningRequestCheck) http.Handler {
	if sink == nil || policy == nil {
		return handler
	}
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		ac, err := evaluatePolicyAndCreateAuditEvent(req, policy, sink)
		if err != nil {
			utilruntime.HandleError(fmt.Errorf("failed to create audit event: %v", err))
			responsewriters.InternalError(w, req, errors.New("failed to create audit event"))
			return
		}

		if !ac.Enabled() {
			handler.ServeHTTP(w, req)
			return
		}

		ctx := req.Context()

		if processed := ac.ProcessEventStage(ctx, auditinternal.StageRequestReceived); !processed {
			audit.ApiserverAuditDroppedCounter.WithContext(ctx).Inc()
			responsewriters.InternalError(w, req, errors.New("failed to store audit event"))
			return
		}

		// intercept the status code
		isLongRunning := false
		if longRunningCheck != nil {
			ri, _ := request.RequestInfoFrom(ctx)
			if longRunningCheck(req, ri) {
				isLongRunning = true
			}
		}
		respWriter := decorateResponseWriter(ctx, w, isLongRunning)

		// send audit event when we leave this func, either via a panic or cleanly. In the case of long
		// running requests, this will be the second audit event.
		defer func() {
			if r := recover(); r != nil {
				defer panic(r)
				ac.SetEventResponseStatus(&metav1.Status{
					Code:    http.StatusInternalServerError,
					Status:  metav1.StatusFailure,
					Reason:  metav1.StatusReasonInternalError,
					Message: fmt.Sprintf("APIServer panic'd: %v", r),
				})
				ac.ProcessEventStage(ctx, auditinternal.StagePanic)
				return
			}

			// if no StageResponseStarted event was sent b/c neither a status code nor a body was sent, fake it here
			// But Audit-Id http header will only be sent when http.ResponseWriter.WriteHeader is called.
			fakedSuccessStatus := &metav1.Status{
				Code:    http.StatusOK,
				Status:  metav1.StatusSuccess,
				Message: "Connection closed early",
			}
			if ac.GetEventResponseStatus() == nil {
				ac.SetEventResponseStatus(fakedSuccessStatus)
				if isLongRunning {
					// A nil ResponseStatus means the writer never processed the ResponseStarted stage, so do that now.
					ac.ProcessEventStage(ctx, auditinternal.StageResponseStarted)
				}
			}
			writeLatencyToAnnotation(ctx)
			ac.ProcessEventStage(ctx, auditinternal.StageResponseComplete)
		}()
		handler.ServeHTTP(respWriter, req)
	})
}

Monica
这段代码是 Kubernetes API Server 的审计日志中间件实现。我来详细解释它的工作原理：

整体功能
WithAudit 是一个 HTTP 中间件装饰器，为所有进入 API Server 的请求添加审计日志功能。

核心参数
复制
handler http.Handler              // 原始的 HTTP 处理器
sink audit.Sink                   // 审计事件的输出目标（存储位置）
policy audit.PolicyRuleEvaluator  // 审计策略评估器（决定哪些请求需要审计）
longRunningCheck                  // 长时间运行请求的检查函数（如 watch 操作）
代码执行流程
1️⃣ 前置检查
复制
if sink == nil || policy == nil {
    return handler
}
如果没有配置审计接收器或策略，直接返回原始 handler，不进行审计。

2️⃣ 评估策略并创建审计事件
复制
ac, err := evaluatePolicyAndCreateAuditEvent(req, policy, sink)
根据请求属性和审计策略评估是否需要审计
创建审计上下文（audit context）
如果失败，返回 500 错误
3️⃣ 检查是否启用审计
复制
if !ac.Enabled() {
    handler.ServeHTTP(w, req)
    return
}
如果策略判定不需要审计此请求，直接执行原始 handler。

4️⃣ 记录请求接收阶段（StageRequestReceived）
复制
if processed := ac.ProcessEventStage(ctx, auditinternal.StageRequestReceived); !processed {
    audit.ApiserverAuditDroppedCounter.WithContext(ctx).Inc()
    responsewriters.InternalError(w, req, errors.New("failed to store audit event"))
    return
}
记录第一个审计阶段：请求已接收
如果记录失败，增加丢弃计数器并返回错误
5️⃣ 判断是否为长时间运行请求
复制
isLongRunning := false
if longRunningCheck != nil {
    ri, _ := request.RequestInfoFrom(ctx)
    if longRunningCheck(req, ri) {
        isLongRunning = true
    }
}
长时间运行的请求（如 kubectl logs -f、watch 操作）需要特殊处理，会产生两个审计事件：

StageResponseStarted：响应开始
StageResponseComplete：响应完成
6️⃣ 装饰 ResponseWriter
复制
respWriter := decorateResponseWriter(ctx, w, isLongRunning)
包装原始的 ResponseWriter，用于拦截状态码和响应内容。

7️⃣ Defer 函数：确保审计事件完整记录
这是最关键的部分，使用 defer 确保无论请求如何结束都会记录审计事件：

处理 Panic 情况
复制
if r := recover(); r != nil {
    defer panic(r)  // 重新抛出 panic
    ac.SetEventResponseStatus(&metav1.Status{
        Code:    http.StatusInternalServerError,
        Status:  metav1.StatusFailure,
        Reason:  metav1.StatusReasonInternalError,
        Message: fmt.Sprintf("APIServer panic'd: %v", r),
    })
    ac.ProcessEventStage(ctx, auditinternal.StagePanic)
    return
}
如果处理请求时发生 panic，记录 StagePanic 阶段。

处理正常/早期关闭情况
复制
fakedSuccessStatus := &metav1.Status{
    Code:    http.StatusOK,
    Status:  metav1.StatusSuccess,
    Message: "Connection closed early",
}
if ac.GetEventResponseStatus() == nil {
    ac.SetEventResponseStatus(fakedSuccessStatus)
    if isLongRunning {
        ac.ProcessEventStage(ctx, auditinternal.StageResponseStarted)
    }
}
如果响应状态为空（连接提前关闭），伪造一个成功状态
对于长时间运行请求，补充记录 StageResponseStarted 阶段
记录完成阶段
复制
writeLatencyToAnnotation(ctx)
ac.ProcessEventStage(ctx, auditinternal.StageResponseComplete)
记录请求延迟到注解中
记录 StageResponseComplete 阶段
8️⃣ 执行原始 Handler
复制
handler.ServeHTTP(respWriter, req)
执行实际的业务逻辑。

审计阶段总结
阶段	说明	何时触发
StageRequestReceived	请求已接收	请求进入时立即记录
StageResponseStarted	响应开始发送	长时间运行请求开始响应时
StageResponseComplete	响应完成	请求处理完成（正常或异常）
StagePanic	发生 Panic	处理请求时发生 panic
关键设计亮点
双重保障：使用 defer + recover 确保审计事件一定会被记录
长时间运行请求特殊处理：记录两个时间点，便于追踪
容错机制：审计失败不影响请求处理（除非是关键阶段）
状态拦截：通过装饰 ResponseWriter 捕获响应状态码
指标统计：记录审计事件丢弃数量
这个设计保证了 Kubernetes 审计日志的完整性和可靠性，是生产环境中追踪 API 操作的关键组件。


关键问题：defer 什么时候触发？
你的疑问很关键！让我用执行时序图解释：

复制
时间线：
┌─────────────────────────────────────────────────────────────┐
│ 1. 进入 WithAudit 的 HandlerFunc                              │
│ 2. 评估策略，创建审计上下文                                    │
│ 3. 记录 StageRequestReceived ✓                               │
│ 4. 注册 defer 函数（但不执行）                                 │
│ 5. 调用 handler.ServeHTTP(respWriter, req) ← 🔥 关键点       │
│    ├─ 进入下一个中间件                                         │
│    ├─ 继续链式调用...                                          │
│    ├─ 最终到达业务 Handler                                     │
│    ├─ 🔄 处理请求（可能很耗时）                                │
│    ├─ 写入响应状态码（触发 WriteHeader）                       │
│    ├─ 写入响应体                                               │
│    └─ 返回 ← handler.ServeHTTP 执行完毕                       │
│ 6. defer 函数执行 ✓                                           │
│    ├─ 记录延迟                                                 │
│    └─ 记录 StageResponseComplete                              │
│ 7. HandlerFunc 返回                                           │
└─────────────────────────────────────────────────────────────┘
核心机制解释
handler.ServeHTTP(respWriter, req) 是阻塞调用
复制
defer func() {
    // ... 审计完成逻辑
}()
handler.ServeHTTP(respWriter, req)  // ← 这里会阻塞，直到整个请求处理完成
// 当上面这行返回时，说明请求已经处理完毕，响应已经发送
关键点：

handler.ServeHTTP() 是同步调用，会等待整个请求处理链完成
包括所有后续中间件、业务逻辑、响应写入
只有当响应完全发送后，这个函数才返回
返回后，defer 函数才执行
实际执行示例
假设有这样的中间件链：

复制
// 中间件链
WithAudit(
    WithAuthentication(
        WithAuthorization(
            BusinessHandler  // 实际处理请求的 Handler
        )
    )
)
执行流程：

复制
// 时刻 T0: 请求到达
WithAudit.ServeHTTP() {
    // T1: 记录 RequestReceived
    ac.ProcessEventStage(StageRequestReceived)
    
    // T2: 注册 defer（不执行）
    defer func() {
        // T10: 最后执行
        ac.ProcessEventStage(StageResponseComplete)
    }()
    
    // T3: 调用下一个 Handler（阻塞在这里）
    WithAuthentication.ServeHTTP() {
        // T4
        WithAuthorization.ServeHTTP() {
            // T5
            BusinessHandler.ServeHTTP() {
                // T6: 处理业务逻辑
                // T7: w.WriteHeader(200)  ← 触发 decorateResponseWriter 拦截
                // T8: w.Write(data)
                // T9: 返回
            }
        }
    }
    // T10: handler.ServeHTTP 返回，defer 执行
}
decorateResponseWriter 的作用
复制
respWriter := decorateResponseWriter(ctx, w, isLongRunning)
handler.ServeHTTP(respWriter, req)  // 传入包装后的 writer
这个包装的 ResponseWriter 会拦截：

WriteHeader(statusCode) - 捕获状态码，记录 StageResponseStarted（长运行请求）
Write(data) - 可以捕获响应体
示例：

复制
// 在业务 Handler 中
func (h *BusinessHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
    // 处理逻辑...
    w.WriteHeader(200)  // ← 这里会触发 decorateResponseWriter.WriteHeader
                        //   记录 StageResponseStarted（如果是长运行请求）
    w.Write([]byte("OK"))
    // 函数返回，逐层返回到 WithAudit
}
验证理解的测试代码
复制
func TestAuditTiming() {
    handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        fmt.Println("T6: 业务逻辑开始")
        time.Sleep(2 * time.Second)  // 模拟耗时操作
        w.WriteHeader(200)
        fmt.Println("T8: 响应已写入")
    })
    
    auditHandler := WithAudit(handler, sink, policy, nil)
    
    auditHandler.ServeHTTP(w, req)
    // 输出顺序：
    // T3: RequestReceived 记录
    // T6: 业务逻辑开始
    // T8: 响应已写入
    // T10: ResponseComplete 记录（defer 执行）
}
总结
你的疑问"此时服务端还没有处理请求"是因为误以为 defer 会立即执行。实际上：

defer 注册时不执行，只是"预约"在函数返回时执行
handler.ServeHTTP() 是阻塞的，会等待整个请求处理完成
当 handler.ServeHTTP() 返回时，请求已经完全处理完毕，响应已发送
此时 defer 执行，记录 StageResponseComplete 是准确的
这就是为什么 defer 能正确记录"响应完成"阶段的原因！

