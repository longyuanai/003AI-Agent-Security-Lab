# ADR-0004：PostgreSQL lease 任务队列优先

- 状态：accepted
- 日期：2026-08-01
- 关联：RUN-001、TM-D-04、ADR-0003

## 上下文

EvaluationRun 需要异步执行、重试、取消、幂等和进程崩溃恢复。初期预期负载不值得同时运营 Redis/RabbitMQ 与 PostgreSQL。

## 候选方案

1. 进程内队列：简单但重启丢任务，不接受。
2. Redis/RabbitMQ/Celery：生态成熟，但增加服务、依赖和 exactly-once 幻觉。
3. PostgreSQL job table + `FOR UPDATE SKIP LOCKED` lease：复用事务数据库并可审计。

## 决策

Preview 采用方案 3。任务语义是 at-least-once；handler 必须幂等。Worker 获取带 owner 和 expiry 的 lease，定期 heartbeat；完成写入以 attempt/version 条件更新。过期 lease 可重领，旧 worker 的迟到结果被 fencing token 拒绝。

只有当实测队列深度、claim latency 或数据库负载连续越过容量阈值，才新增 ADR 评估专用 broker。

## 安全与隐私影响

任务表只保存引用和最小配置，不存 secret/raw prompt。租赁和取消均带 tenant/run 权限并写 audit。限制单租户并发、重试次数和总预算。

## 验证

- 多 worker 竞争时一 attempt 只有一个有效 owner。
- 崩溃/超时后可重领；迟到回传不能覆盖新 attempt。
- 幂等 key 并发创建只产生一个逻辑 run。
- cancel 与 complete 竞争保持合法终态。

## 回滚

停止 worker 后任务保留在数据库；回滚到兼容 schema 的 worker 可继续领取。禁止通过清空队列表回滚。

## 后果

接受 PostgreSQL 轮询和 at-least-once 设计，换取较少基础设施。必须正确实现幂等与 fencing，不能声称 exactly once。

