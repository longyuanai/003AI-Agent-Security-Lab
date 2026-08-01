# 003 AI-Agent-Security-Lab · 商用化实施清单

> 更新日期：2026-08-01
> 当前分支：`codex/agent-lab-benchmark-v2`
> 主规范：[commercial-spec.md](commercial-spec.md)
> 冻结接口：shared-llm-core v0.1 §1–§6、既有 Finding schema、`scan --json` envelope
> 状态说明：`done` 已验证并推送；`in_progress` 当前阶段；`planned` 尚未开始；`blocked` 存在外部阻断。

## 1. 已完成基线

| ID | 完成项 | 状态 | 证据 |
|----|--------|------|------|
| SCEN-001 | 5 个内置脆弱 Agent | done | target/CLI/tests |
| ATTACK-001 | 10 类攻击与 detector 覆盖 | done | attacks/detector/tests |
| SAND-001 | 本地 subprocess PoC 沙箱 | done | sandbox/tests；非生产安全边界 |
| METRIC-001 | 5 × 10 ASR Markdown/JSON | done | metrics/tests |
| MULTI-003-A | 五角色 MultiAgent 编排 | done | multi_agent/orchestrator/tests |
| SCEN-003-A | 5 个 v0.5 高级场景 | done | scenarios/tests |
| REPORT-003-A | 跨场景 Finding 关联报告 | done | report/tests |
| LAB-CLI-001 | IntegrationGateway CLI envelope | done | scan/cli envelope tests |
| LAB-LIVE-001 | fake/OpenAI/Anthropic provider 切换 | done | env-gated tests |
| PHASE2-ATLAS | ATLAS 安全模板与插件注册 | done | atlas/entry points/tests |
| PHASE2-JUDGE | 显式密钥启用 LLM Judge | done | judge + mock tests |
| PHASE2-REPORT | ATLAS Markdown/JSON 报告 | done | report/CLI tests |
| BENCH-001 | AttackCase 与 DeliveryStrategy 分离 | done | `5de994a` |
| BENCH-002 | 客观 Success Oracle 与安全状态效果 | done | `8890994` |
| BENCH-003 | 五 Agent 合法/攻击任务套件 | done | `6004978` |
| BENCH-004 | ASR/Utility/Detector/Judge 指标 | done | `12ae9dd` |

最近完整回归基线：246 tests passed。每个后续里程碑必须重新执行完整回归，不能沿用该数字声称通过。

## 2. M0 · 商用技术基线

| ID | 任务 | 状态 | 验收 |
|----|------|------|------|
| COMM-DOC-001 | 商用架构、安全、隐私、API、SLO 和 DoD | done | 文档一致、链接检查通过、246 tests passed |
| COMM-THREAT-001 | STRIDE/LINDDUN 威胁模型 | done | 6 个信任边界、24 个 STRIDE/LINDDUN 风险与发布测试清单 |
| COMM-ADR-001 | ADR 模板和首批架构决策 | done | 6 个 accepted ADR；链接检查与 246-test M0 回归通过 |

## 3. M1 · Benchmark 产品内核

| ID | 任务 | 状态 | 验收 |
|----|------|------|------|
| BENCH-005 | 隐私安全 RunRecord + JSON evidence | done | 固定 seed/版本/hash；9 tests；255-test 全量回归通过 |
| BENCH-006 | Benchmark Markdown 报告 | done | 原子写入、隐私声明、objective evidence、6 tests；261 passed |
| BENCH-007 | `benchmark` CLI | done | 8 tests；offline/live gating、dry-run、报告/evidence、scan envelope；269 passed |
| BENCH-008 | 文档、全量回归与可复现 smoke | done | compileall、269 passed、同 seed fingerprint 一致、报告产物验证 |

M1 状态：**done（2026-08-01）**。冻结接口不变；269 tests passed；输出无原始 prompt、对话历史和 secret；BENCH-005/006/007 均已独立 commit/push。

## 4. M2 · 可部署服务

| ID | 任务 | 状态 | 验收 |
|----|------|------|------|
| API-001 | `/v1` schema、统一错误和 request ID | done | live/ready、请求边界、统一错误、13 tests；282 passed |
| STORE-001 | Repository ports + SQLite/PostgreSQL adapters | done | tenant-bound Repository、Alembic drift check、14 tests；296 passed |
| RUN-001 | EvaluationRun 状态机、lease、retry、cancel | done | 幂等、过期重领、fencing、取消、14 tests；310 passed |
| ART-001 | 文件/S3-compatible artifact store | done | 原子文件 adapter/port、sha256、TTL、symlink/traversal、11 tests；321 passed |
| OBS-001 | JSON 日志、metrics、live/ready health | done | allowlist JSON 日志、route-template metrics、9 tests；330 passed |
| E2E-001 | API → worker → evidence → report | done | 单租户 API、持久化 worker、重启、真实 Uvicorn、12 tests；342 passed |
| M2-REL-001 | 单机部署、迁移、SQLite 备份恢复与说明 | done | Uvicorn/Alembic、非覆盖恢复、SHA-256、6 tests；348 passed |

M2 状态：**done（2026-08-01）**。服务可单机部署；任务不因进程重启丢失；SQLite 备份恢复已实际演练。PostgreSQL 生产恢复演练仍是 Commercial Preview 门禁，不属于本地 M2 自动化替代项。

## 5. M3 · 企业身份与安全执行器

| ID | 任务 | 状态 | 验收 |
|----|------|------|------|
| AUTH-001 | API key hash、OIDC principal、RBAC | planned | 权限矩阵和拒绝路径测试 |
| TENANT-001 | tenant context 与 repository 强制隔离 | planned | 跨租户/IDOR 测试为发布阻断项 |
| QUOTA-001 | tenant/project 并发、速率和成本配额 | planned | 超额明确拒绝且可审计 |
| EXEC-001 | 容器 Sandbox Broker/Runner | planned | non-root、read-only、cap-drop、资源限制 |
| NET-001 | 默认 deny-egress + SSRF 防护 | planned | DNS rebinding、private/link-local、redirect 测试 |
| SECRET-001 | secret reference 与全链路脱敏 | planned | log/error/evidence 泄漏扫描 |

M3 退出条件：完成跨租户安全测试、进程树清理测试和默认断网验证；subprocess 模式不能用于生产多租户。

## 6. M4 · 真实生态与 CI

| ID | 任务 | 状态 | 验收 |
|----|------|------|------|
| SDK-001 | Target/Attack/Detector/Judge adapter SDK | planned | 版本协商、能力声明、认证测试套件 |
| ADAPT-001 | 真实 Agent adapter 1 | planned | 授权 fixture 环境 E2E |
| ADAPT-002 | 真实 Agent/MCP adapter 2 | planned | 授权 fixture 环境 E2E |
| CI-001 | CI benchmark 与基线差异门禁 | planned | 可配置阈值、SARIF/JUnit 或稳定 JSON 输出 |
| REGRESS-001 | SuiteVersion 与基准比较 | planned | immutable manifest、回归趋势与兼容测试 |

M4 退出条件：至少两个真实 adapter 通过同一 certification suite；完成一个内部或授权客户试点。

## 7. M5 · Commercial Preview

| ID | 任务 | 状态 | 验收 |
|----|------|------|------|
| UI-001 | 最小 Web 控制台 | planned | 项目、运行、Finding、报告，不绕过 API 权限 |
| AUDIT-001 | append-only audit 与导出 | planned | 登录、授权、配置、运行、下载全覆盖 |
| OPS-001 | Dashboard、告警、runbook | planned | SLO 可见，关键告警演练 |
| BACKUP-001 | 备份恢复与删除验证 | planned | RPO/RTO 演练记录 |
| DIST-001 | 安装、升级、回滚、配置文档 | planned | 全新环境和上一版本升级 smoke |
| PILOT-001 | 单租户试点 | planned | 用户验收、缺陷闭环、安全评审 |

## 8. M6 · GA 门禁

| ID | 任务 | 状态 | 验收 |
|----|------|------|------|
| SUPPLY-001 | 锁定依赖、SBOM、provenance、签名发布 | planned | CI 可验证制品来源与 checksum |
| SEC-REVIEW-001 | 独立渗透测试与修复 | planned | Critical/High 清零或正式风险接受 |
| PERF-001 | 负载、容量和降级测试 | planned | 达到商用 SLO，超载不丢任务 |
| COMPLY-001 | 隐私、保留、删除、ToS 与授权流程 | planned | 法务/安全审核记录 |
| SUPPORT-001 | 兼容政策、漏洞响应和支持 SLA | planned | 对外发布文档齐全 |

GA 禁止条件：跨租户问题、secret 泄漏、执行器默认可联网、未修复 Critical/High、未验证恢复、冻结契约破坏。

## 9. 每项任务执行规范

1. 开工前读取相关规范、接口和现有测试。
2. 修改范围最小；新增生产依赖必须先写 ADR。
3. 每个 issue 至少 3 个有意义的 test function；安全关键 issue 应覆盖拒绝路径。
4. Windows 验证命令：

```powershell
& 'C:\Users\15072\AppData\Local\Programs\Python\Python314\python.exe' `
  -m pytest tests/ `
  --basetemp=C:/pytest-tmp/003-commercial `
  -o addopts= `
  -q --tb=short
```

5. 不在测试中访问真实 LLM 或未授权外网。
6. 不提交 API Key、Token、客户数据或真实恶意 payload。
7. 每个任务独立 commit，并推送 `codex/agent-lab-benchmark-v2`。
8. 回报：Files / Tests / Compliance / Known Issues / Rollback。

## 10. 当前执行顺序

1. M0 商用文档：done。
2. M1 Benchmark 产品内核：done。
3. M2 可部署服务：done。
4. 下一任务 `AUTH-001`：API key/OIDC principal 与 RBAC。
5. 随后执行 `TENANT-001`、`QUOTA-001`、`EXEC-001`、`NET-001`、`SECRET-001`。

不得为了追求“商用”一次性引入 Kubernetes、Redis、消息队列和多个微服务。只有测得模块化单体无法满足容量或隔离目标时，才通过 ADR 拆分。
