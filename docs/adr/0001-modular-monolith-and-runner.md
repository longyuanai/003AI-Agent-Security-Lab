# ADR-0001：模块化单体控制面与独立执行器

- 状态：accepted
- 日期：2026-08-01
- 关联：COMM-DOC-001、TM-E-02、TM-E-05

## 上下文

PoC 是单进程 CLI。商用版本需要 API、持久化、身份、任务调度和隔离执行，但当前团队与负载不支持一开始维护多个微服务。危险任务又不能与控制面共享权限和进程边界。

## 候选方案

1. 单进程应用：开发简单，但控制面可被任务拖垮或反控，不接受。
2. 全微服务：独立扩缩容，但增加部署、网络、事务和观测成本，当前没有数据证明需要。
3. 模块化单体控制面 + 独立 Runner：保持交付速度，同时隔离最危险边界。

## 决策

采用方案 3：API、application services 和 metadata repositories 构成模块化单体；Worker 在 Preview 可同镜像部署，但通过持久化 lease 协作；Sandbox Runner 是独立 Linux 进程/容器和最小权限身份。

Domain 不依赖 HTTP、数据库、容器或 LLM SDK。模块间通过显式 application ports 通信，禁止跨模块直接查询表。仅在满足任一条件时评估拆服务：单模块独立扩容持续超过 3 倍、发布节奏冲突连续发生、故障隔离无法达到 SLO，或安全边界要求独立部署。

## 安全与隐私影响

Runner 不获得控制面数据库、OIDC、GitHub 或对象存储管理凭据。控制面只接受经过 schema 和大小验证的归一化结果。对应 TM-E-02、TM-E-05、TM-I-02。

## 验证

- Import boundary 测试保证 domain 不依赖 adapters/API。
- API 进程不能直接调用危险 Target tool。
- Runner 被终止或伪造结果时，控制面保持可用并拒绝无效结果。

## 回滚

各模块仍在同一 Python distribution；可禁用 service 入口并回到 CLI 离线模式。Runner adapter 可切回仅用于开发的 subprocess，但不得标记为生产模式。

## 后果

接受一个代码库中的明确边界和少量重复 DTO，换取更低运维复杂度。跨模块事务由 application service 管理。

