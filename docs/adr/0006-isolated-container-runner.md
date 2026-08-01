# ADR-0006：独立 Linux 容器 Runner

- 状态：accepted
- 日期：2026-08-01
- 关联：EXEC-001、NET-001、TM-I-04、TM-D-02、TM-E-02

## 上下文

现有 Windows/subprocess sandbox 提供超时和应用层 guard，但共享宿主权限，不能执行多租户或客户提供的不受信任代码。

## 候选方案

1. subprocess：保留用于单元测试和可信 fixture，不满足生产隔离。
2. Docker/OCI 容器：适合单租户 Preview，生态和资源控制成熟。
3. gVisor/Kata/microVM：隔离更强，但启动、平台和运维成本更高。

## 决策

Commercial Preview 的企业单租户执行器采用独立 Linux OCI Runner；SaaS 或任意客户代码必须使用方案 3，并在开放前完成新 ADR 与逃逸测试。

Runner 固定要求：non-root、read-only rootfs、tmpfs workspace、drop ALL capabilities、no-new-privileges、seccomp/LSM、PID/CPU/RAM/disk/time/output limit、默认 deny egress、无 Docker socket/宿主 mount/控制面 secret。镜像用 digest 固定并验证签名。

Broker 只使用结构化参数调用 runtime，不通过 shell 拼接命令。任务结束、超时或取消时销毁完整容器隔离单元。

## 安全与隐私影响

缓解 TM-I-04、TM-D-02、TM-E-02，但容器共享 kernel 的残余风险在 Preview 通过单租户和受控任务降低。Runner 输出经过 schema/size allowlist；工作区结束即销毁。

## 验证

- non-root、capability、mount、read-only、network 和资源限制的主动断言。
- fork/loop/memory/disk/output/timeout fixture，确认完整进程树和资源被清理。
- loopback/private/link-local/redirect/DNS rebinding egress 测试。
- 宿主路径、socket、metadata credential 和其他任务 workspace 不可达。

## 回滚

执行器 adapter 可切换，但生产配置禁止选择 subprocess。Runner 发布回滚使用上一签名镜像 digest；任务 schema 至少兼容前一个 minor version。

## 后果

生产执行依赖 Linux/OCI runtime；Windows 仅作为开发客户端。SaaS 上线前仍需更强 runtime 和独立渗透测试。

