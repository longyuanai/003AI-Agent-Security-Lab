# AI-Agent-Security-Lab 商用技术基线

> 文档版本：1.0-draft  
> 生效日期：2026-08-01  
> 目标版本：Commercial Preview → GA  
> 规范级别：本文件是商用化实施与验收的主规范；与历史 PoC 说明冲突时，以本文件为准。

配套安全分析见 [threat-model.md](threat-model.md)，关键技术选择见 [ADR 索引](adr/README.md)。

## 1. 产品定义与边界

AI-Agent-Security-Lab 是面向 AI Agent 的安全评测与回归平台。平台在授权、隔离的环境中运行安全测试任务，使用客观状态效果、规则检测器和可选 LLM Judge 分别评估攻击成功、检测质量与合法任务效用，并生成可审计、可复现的证据。

### 1.1 商用版本必须提供

- 五类内置 Agent 的离线演示和回归基准。
- 插件式 Target、Attack、Detector、Judge 和 Sandbox 接口。
- 攻击任务与合法对照任务成对执行。
- ASR、Utility、False Refusal、TPR、FNR、FPR 和 Judge Agreement 指标。
- CLI、版本化 HTTP API 和 CI 友好的机器可读输出。
- 按租户隔离的项目、评测运行、Finding、证据和报告。
- 安全执行器、资源配额、超时、取消和完整审计。
- 默认不持久化原始提示词、模型消息或 Agent 对话历史。
- 本地单机部署和企业自托管部署。

### 1.2 明确不承诺

- 不替代人工红队、代码审计或合规认证。
- 不对未授权公网目标执行测试。
- 不把 Detector 或 LLM Judge 的判断等同于攻击客观成功。
- 不宣称覆盖未知攻击或证明目标“绝对安全”。
- SaaS 首版不允许客户提交任意宿主机代码；不受信任代码仅能进入强隔离执行器。

## 2. 当前基线与商用差距

| 能力 | 当前状态 | Commercial Preview 门槛 | GA 门槛 |
|------|----------|-------------------------|---------|
| 内置 Agent / Attack | 5 Agent、10 Attack | 保持兼容并版本化 | 插件兼容策略和弃用周期 |
| Benchmark | M1 已完成：任务套件、Oracle、指标、evidence、CLI | 已达到 | 基准版本锁定与回归比较 |
| 报告 | 隐私安全 Markdown/JSON 已完成 | 已达到 | 签名、保留策略、导出审计 |
| API | CLI/IntegrationGateway 适配 | 稳定的 `/v1` API | 向后兼容和限流 |
| 持久化 | 文件输出 | SQLite 本地 + PostgreSQL 生产 | 迁移、备份恢复、归档 |
| 身份权限 | 无 | API key + 项目级 RBAC | OIDC/SSO、细粒度审计 |
| 隔离 | subprocess PoC | 容器执行器、默认断网 | 多租户强隔离与逃逸测试 |
| 可观测性 | 测试与 CLI 日志 | 结构化日志、metrics、健康检查 | SLO、告警、追踪、运行手册 |
| 供应链 | Python 包 | 锁定依赖、SBOM、扫描 | 签名发布、漏洞响应 SLA |

当前 Python 模块是商用内核的起点，不应直接作为公网多租户服务暴露。

## 3. 架构原则

1. **安全默认值**：离线、拒绝公网 egress、最小权限、最短保留期。
2. **客观成功优先**：Attack Success 由状态效果 Oracle 判定；Detector 与 Judge 是独立信号。
3. **隐私最小化**：存哈希和归一化效果，不默认存原始输入与对话。
4. **可复现**：每次运行固定 suite 版本、seed、配置摘要、镜像 digest 和规则版本。
5. **契约稳定**：冻结 shared-llm-core v0.1 §1–§6 和既有 scan envelope；新增能力走版本化接口。
6. **模块化单体优先**：先交付一个可部署、可维护的服务；达到明确负载门槛后再拆服务。
7. **执行面隔离**：控制面不得直接执行目标 Agent 产生的任意代码或工具参数。

## 4. 目标架构

```text
CLI / CI / Web UI
        |
        v
Versioned API (/v1) ---- AuthN/AuthZ ---- Audit Log
        |
        v
Application Services
  Project / Suite / Run / Finding / Report
        |
        +---- PostgreSQL (metadata, tenant-scoped)
        +---- Object Store (reports, redacted evidence)
        +---- Job Lease Table (retry, cancel, idempotency)
        |
        v
Sandbox Broker ---- signed job ---- Isolated Runner
                                      |-- target adapter
                                      |-- attack delivery
                                      |-- detector/oracle/judge
                                      `-- normalized evidence only
```

### 4.1 进程边界

- **Control API**：验证请求、授权、创建任务、查询结果，不执行危险工具。
- **Worker**：租赁任务、准备运行清单、调用 Sandbox Broker、聚合结果。
- **Sandbox Runner**：一次任务一个临时工作区；默认断网；结束后销毁。
- **Report Renderer**：只消费归一化 evidence，不读取目标对话历史。

Commercial Preview 可将 API 与 Worker 部署在同一镜像中，但代码依赖方向必须保持边界，方便后续独立扩容。

### 4.2 Python 包边界

```text
ai_agent_lab.domain       # 不依赖 CLI、数据库、网络 SDK
ai_agent_lab.application  # 用例编排、端口定义、事务边界
ai_agent_lab.adapters     # DB、对象存储、LLM、Target、Sandbox
ai_agent_lab.api          # HTTP schemas、认证、错误映射
ai_agent_lab.cli          # 本地与 CI 入口
ai_agent_lab.report       # 只接受隐私安全 evidence
```

现有模块逐步迁移，不进行一次性重写；`target.py`、`detector.py` 和冻结契约通过兼容适配层保留。

## 5. 核心领域模型

所有持久化实体必须具有 `id`、`tenant_id`、`created_at`；可变实体额外具有 `updated_at` 和乐观锁版本。

| 实体 | 关键字段 | 约束 |
|------|----------|------|
| Tenant | name, status, retention_policy | 所有业务数据的隔离根 |
| UserPrincipal | subject, tenant_id, roles | 不存身份提供商密码 |
| Project | name, target_policy, created_by | 项目成员才能读取 |
| SuiteVersion | suite_id, version, manifest_hash | 发布后不可变 |
| EvaluationRun | project_id, suite_version, seed, status | 状态机单向流转 |
| TaskRun | run_id, agent, attack, strategy, timings | 不存 raw prompt |
| StateEffect | task_run_id, boundary, resource, action, target | 归一化、非操作性 |
| Finding | shared contract fields + run_id | 不修改冻结 Finding schema |
| EvidenceManifest | hashes, rule_versions, runtime | 可复现，无秘密信息 |
| ReportArtifact | run_id, format, object_key, sha256 | 下载须授权并审计 |
| AuditEvent | actor, action, resource, result, request_id | append-only |

### 5.1 运行状态机

```text
queued -> preparing -> running -> evaluating -> completed
   |          |           |            |
   +----------+-----------+------------+-> failed
   +-------------------------------------> cancelled
```

- 终态不可回退。
- 重试生成新的 attempt，不覆盖旧 attempt。
- `idempotency_key + tenant_id` 在 24 小时窗口内唯一。
- Worker 通过带过期时间的 lease 获取任务；超时任务可安全重领。

## 6. API 契约

### 6.1 版本与格式

- 商用 API 前缀为 `/v1`；实验接口使用 `/experimental`。
- JSON 字段使用 `snake_case`，时间使用 UTC RFC 3339。
- 写请求接受 `Idempotency-Key`；响应包含 `X-Request-Id`。
- 列表使用不透明 cursor 分页，禁止无界查询。
- 错误统一为：

```json
{
  "error": {
    "code": "run_not_found",
    "message": "Evaluation run was not found",
    "request_id": "req_...",
    "details": {}
  }
}
```

错误信息不得包含 API key、内部路径、原始 prompt、堆栈或数据库语句。

### 6.2 Commercial Preview 端点

| 方法 | 路径 | 权限 | 说明 |
|------|------|------|------|
| GET | `/v1/health/live` | public | 进程存活，不探测外部依赖 |
| GET | `/v1/health/ready` | operator | 数据库、存储、执行器就绪 |
| POST | `/v1/projects` | admin | 创建项目 |
| GET | `/v1/projects` | viewer | 当前租户项目列表 |
| POST | `/v1/runs` | operator | 创建评测运行 |
| GET | `/v1/runs/{id}` | viewer | 状态与摘要 |
| POST | `/v1/runs/{id}/cancel` | operator | 幂等取消 |
| GET | `/v1/runs/{id}/findings` | viewer | 分页 Finding |
| GET | `/v1/runs/{id}/reports/{format}` | viewer | 授权下载 |
| GET | `/v1/suites` | viewer | 已发布 suite 版本 |

既有 `scan --json` envelope 继续用于 IntegrationGateway；不得在没有版本升级的情况下删除或重命名字段。

## 7. 身份、权限与租户隔离

### 7.1 角色

- `viewer`：读取项目、运行和报告。
- `operator`：创建、取消运行，不得管理凭据。
- `admin`：管理项目成员、策略和 retention。
- `auditor`：只读审计事件和合规导出。

### 7.2 强制规则

- 授权在 Application Service 入口执行，不能只依赖 UI。
- Repository 查询必须强制携带 `tenant_id`，禁止先按 ID 查询再做租户判断。
- API key 只存带独立 salt 的不可逆哈希；显示一次后不可恢复。
- 生产环境支持 OIDC；不自行保存用户密码。
- 跨租户访问测试、IDOR 测试和权限矩阵测试属于发布阻断项。

## 8. 数据安全与隐私

### 8.1 数据分类

| 级别 | 示例 | 默认处理 |
|------|------|----------|
| Public | 公开 ATLAS ID、产品文档 | 可长期保留 |
| Internal | 配置、运行指标 | 按租户保留策略 |
| Confidential | Target endpoint、项目名称 | 加密、最小访问 |
| Restricted | API key、可能含客户数据的输入 | 不记录或秘密存储 |

### 8.2 证据最小化

默认 Evidence 只能包含：

- suite/task/agent/attack/strategy 标识符；
- 输入的 SHA-256，不包含输入正文；
- 归一化工具名与 StateEffect；
- detector/judge/oracle 结果及规则版本；
- latency、token/cost 统计和运行环境摘要；
- 报告与清单自身的 SHA-256。

禁止默认持久化：system prompt、user prompt、tool 原始返回、模型 messages、完整对话、API key、Authorization header、客户文件正文。

若企业客户显式启用原始证据，必须同时满足：项目级开关、RBAC、字段级加密、独立密钥、访问审计、可配置 TTL 和删除验证；该能力不属于首个 Commercial Preview。

### 8.3 保留与删除

- 默认 metadata 90 天、报告 30 天、审计 180 天；租户可缩短。
- 删除采用异步 tombstone，24 小时内从在线存储删除，并按备份周期最终清除。
- 报告下载使用短期签名 URL 或经过 API 授权的流式下载。

## 9. 执行隔离与网络策略

### 9.1 本地开发模式

现有 subprocess sandbox 仅用于可信、合成输入的本地测试。它不是多租户安全边界，CLI 和文档必须明确显示该限制。

### 9.2 商用执行器最低要求

- 每个任务独立容器和临时工作区。
- 非 root、只读 root filesystem、drop all capabilities、no-new-privileges。
- CPU、memory、PID、文件大小、运行时长和输出大小限制。
- 默认 deny egress；DNS、HTTP 和目标地址均受 allowlist 约束。
- 禁止挂载 Docker socket、宿主目录、云 metadata 凭据和控制面 secrets。
- 镜像使用 digest 固定并验证签名；任务清单带签名和过期时间。
- 超时或取消后必须杀死完整进程树并销毁网络、volume 和凭据。
- 执行器回传归一化事件，控制面拒绝超出 schema/大小限制的结果。

### 9.3 GA 强化

公网 SaaS 或不受信任代码执行必须使用 gVisor、Kata Containers 或 microVM 等更强边界，并完成独立逃逸测试。仅 Docker 默认配置不满足该场景。

## 10. LLM 与 Target 连接器

- 默认 `offline`，只有显式配置 provider、model、endpoint 和 secret reference 才能联网。
- Secret 不通过任务 payload 或环境转储进入 evidence。
- Endpoint 必须经过 SSRF 校验：HTTPS、域名 allowlist、解析后地址检查、禁止 link-local/private ranges（除非管理员显式批准私网连接器）。
- 每个 provider 配置超时、重试上限、并发和成本预算。
- 记录 provider/model 标识和 token 统计，不记录请求正文。
- Judge 超时或失败返回 `unavailable`，不得默认为安全或攻击成功。
- Target adapter 必须声明 capabilities、所需网络、数据分类和支持的取消语义。

## 11. 可观测性与运行保障

### 11.1 信号

- 结构化 JSON 日志：timestamp、level、service、request_id、tenant_id_hash、run_id、event、result。
- Metrics：请求量/错误率/延迟、队列深度、任务状态、sandbox 启动失败、超时、重试、LLM 成本。
- Trace：API → worker → sandbox broker 的相关 ID；不采集 prompt 内容。
- Audit：认证、授权拒绝、配置变更、run 创建/取消、报告下载、密钥轮换。

### 11.2 SLO

| 指标 | Commercial Preview | GA |
|------|--------------------|----|
| Control API 月可用性 | 99.5% | 99.9% |
| 创建任务 API p95 | < 500 ms | < 300 ms |
| 已接收任务不丢失 | 99.99% | 99.999% |
| 取消信号生效 p95 | < 30 s | < 10 s |
| 报告生成成功率 | ≥ 99% | ≥ 99.9% |
| 同配置离线复现率 | ≥ 99% | ≥ 99.5% |

备份目标：生产 metadata RPO ≤ 24 小时、RTO ≤ 4 小时；GA 前必须完成并记录一次恢复演练。

## 12. 测试与发布门槛

每个提交必须通过适用的单元测试；每个里程碑必须通过完整门禁。

### 12.1 必测层级

- 单元测试：domain、状态机、策略、序列化、脱敏。
- 契约测试：shared-llm-core、IntegrationGateway、CLI envelope、`/v1` API。
- 集成测试：数据库迁移、对象存储、worker lease、报告下载。
- 安全测试：RBAC、跨租户、SSRF、路径穿越、命令参数、secret redaction、压缩炸弹和资源耗尽。
- 容错测试：进程崩溃、超时、重复消息、部分写入、Judge 不可用。
- 端到端测试：创建项目 → 运行 → evidence → report → audit。

### 12.2 发布阻断项

- 全量测试失败或冻结契约变化。
- Critical/High 已知依赖漏洞无书面例外和补偿控制。
- evidence、日志或错误响应出现 secret、raw prompt 或对话历史。
- 跨租户读取、未授权报告下载或执行器默认可访问公网。
- 数据库迁移不可向前执行，或没有已验证回滚/恢复方案。
- 未生成锁定依赖清单、SBOM、构建 provenance 或制品校验和。

### 12.3 质量目标

- 新增/修改 domain 和 application 代码行覆盖率 ≥ 90%。
- 核心状态机、租户隔离、授权和证据脱敏分支覆盖率 100%。
- flaky test 比率 < 1%；网络依赖在测试中全部 mock 或使用本地 fixture。
- Windows 开发测试和 Linux CI 均通过；生产执行器以 Linux 为准。

## 13. 供应链与安全开发生命周期

- 依赖必须固定版本并经过许可证与漏洞审查；新增生产依赖需要 ADR。
- CI 执行测试、lint、类型检查、secret scan、SAST、依赖扫描和 SBOM 生成。
- 发布制品使用不可变版本、校验和和签名；容器使用非 root 最小镜像。
- 每个安全问题有严重度、负责人、修复 SLA 和披露流程。
- Critical：24 小时缓解、72 小时修复计划；High：7 天；Medium：30 天。
- 发布前完成威胁模型评审；GA 前完成独立渗透测试。

## 14. 部署拓扑

### 14.1 Community / 开发

- CLI + 本地文件 evidence。
- SQLite 可选。
- 仅运行合成 fixture；subprocess sandbox 明确标记为非安全边界。

### 14.2 Enterprise 单租户

- 一个租户一个部署。
- API/Worker + PostgreSQL + S3-compatible object store + isolated runner。
- OIDC、私有镜像仓库、客户自有密钥和网络 allowlist。

### 14.3 SaaS 多租户

只有以下条件全部满足后才开放：强隔离 runner、租户隔离测试、限流配额、审计、删除验证、恢复演练、独立渗透测试和法律条款。首个 Commercial Preview 默认不开放任意代码执行。

## 15. 兼容与迁移

- `shared-llm-core` v0.1 §1–§6 和既有 Finding 字段保持冻结。
- 当前 `target.py`、`detector.py`、`scan_payload()` 和 CLI scan envelope 保留兼容测试。
- 新 schema 采用 additive change；删除字段至少经历一个 minor version 的 deprecated 周期。
- 数据库迁移只允许向前追加；破坏性迁移拆成 expand → migrate → contract 三阶段。
- 报告 schema 带 `schema_version`；读取器至少支持当前和前一个 minor version。

## 16. 商用交付阶段

### M0 · 技术基线

- 本规范、威胁模型、ADR 模板、数据分类和发布门禁。
- 验收：文档一致、任务可追踪、每项有退出条件。

### M1 · Benchmark 产品内核

- 隐私安全 evidence、Markdown/JSON 报告、benchmark CLI、固定 seed、离线默认。
- 验收：冻结接口不变，完整回归通过，产物不含 raw prompt/history。

### M2 · 可部署服务

- `/v1` API、持久化、任务状态机、幂等、健康检查、结构化日志。
- 验收：API 契约、迁移、重启恢复和端到端测试通过。

### M3 · 企业身份与隔离

- API key/OIDC、RBAC、tenant scoping、容器 runner、网络 deny-by-default。
- 验收：权限矩阵、跨租户、SSRF、secret redaction、进程树清理测试通过。

### M4 · 真实生态接入

- 插件 SDK、至少两个真实 Agent/MCP adapter、CI 集成、基准版本比较。
- 验收：adapter certification suite 和真实但授权的试点完成。

### M5 · Commercial Preview

- Web 最小控制台、审计导出、配额、监控告警、备份恢复、安装升级文档。
- 验收：试点客户运行、SLO 仪表板、恢复演练、安全评审完成。

### M6 · GA

- 签名发布、SBOM、漏洞响应、独立渗透测试、支持政策和兼容承诺。
- 验收：所有发布阻断项清零，由产品、安全、运维共同签字。

## 17. Definition of Done

任务只有在以下条件全部满足时才能标记完成：

1. 代码、测试、文档和迁移属于同一可审阅变更。
2. 适用测试在规定 Windows 命令及 Linux CI 中通过。
3. 没有修改冻结契约，或已完成明确版本升级流程。
4. 威胁、隐私、租户和失败路径均有测试或书面说明。
5. CLI/API smoke 已实际运行并保存结果。
6. Git 提交范围单一，已推送远端功能分支。
7. 回报包含 Files、Tests、Compliance、Known Issues 和回滚方式。

## 18. 决策记录

| 日期 | 决策 | 原因 |
|------|------|------|
| 2026-08-01 | 采用模块化单体 + 独立执行器 | 降低早期运维复杂度，同时保留安全进程边界 |
| 2026-08-01 | Oracle 与 Detector/Judge 分离 | 避免用主观检测结果定义攻击成功 |
| 2026-08-01 | 默认不保存 raw prompt/history | 降低隐私、合规和泄密风险 |
| 2026-08-01 | Commercial Preview 先做单租户 | 多租户任意代码执行风险过高，需在强隔离后开放 |
