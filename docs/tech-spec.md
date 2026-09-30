# 001 AI-Agent-Security-Lab 技术规范

版本：1.0 / 2026-09-23，重组后的开发基线。API 来源仍为 `003`，包仍为 ai_agent_lab。
本规范替代旧商业规范中的工作区、当前状态与任务优先级；旧版本保存在 archive。代码和现场测试决定已实现状态，本文明确标注后续目标。

## 1. 产品目标与边界

面向开发自有/授权 Agent 的团队，提供可复现的安全测试、任务效用评估、证据与修复回归。第一交付形态是受控本地/内网评估工具；多租户托管服务需单独通过权限和执行隔离验收。

SOC 已归入 `modules/soc-analysis`，用于事件归一化、规则判断、关联分析和报告。它保留独立 Git 与 ai_soc_agent 包，不再作为第四个独立产品推进。现有 SSH/主机日志规则不能直接代表 Agent 工具滥用检测。

不在首阶段建设：全功能 SOC 控制台、任意互联网目标扫描、自动化客户系统处置、未经验证的恶意代码执行服务。

## 2. 当前代码入口

| 位置（相对本仓） | 当前职责 |
|---|---|
| src/ai_agent_lab/cli.py | 命令入口 |
| src/ai_agent_lab/runner.py、orchestrator.py | 实验与执行组织 |
| src/ai_agent_lab/attacks.py、scenarios | 攻击/场景实现 |
| src/ai_agent_lab/oracle.py、benchmark_metrics.py、task_suites.py | 判定与基准 |
| src/ai_agent_lab/api/app.py、application/service.py | API 与应用服务 |
| src/ai_agent_lab/auth.py、application/authorized.py | 认证/授权边界 |
| src/ai_agent_lab/storage/run_repository.py、application/service.py | 租户作用域存储与 process_next 任务执行；当前无 jobs.py 或独立队列消费者 |
| src/ai_agent_lab/sandbox.py | 实验子进程约束 |
| src/ai_agent_lab/report | JSON/Markdown/证据报告 |
| modules/soc-analysis/src/ai_soc_agent | SOC 能力 |

身份与租户隔离代码已有未提交修改和 tests/test_tenant_isolation.py；不能沿用旧文档“尚未实现”的概括，也不能在未做部署验证时写“生产完备”。A0 现场复核见下。

2026-09-27 A0 本机验收完成：已复核现有差异与授权路径，七文件基线 100 passed，新增 56 个权限负例后联合 156 passed；原有产品源码与 tenant 测试未改。新测试 Ruff、独立临时开发环境中的 strict mypy 及 git diff --check 均通过。路径表、负例及部署限制见 [A0 基线](a0-authorization-baseline-20260927.md)；这些本机结果不构成 SaaS 多租户验收。

## 3. 输入与输出

当前可用入口：根 `suite.py agent benchmark -- --help`、`suite.py agent soc -- --help`。实际参数以帮助与 CLI 为准。

产品输入应包含受控目标、场景/数据集版本、随机种子（适用时）、工具权限、预算/超时和测试配置。接入新外部 Agent 时先定义适配协议和授权范围，不把任意用户 URL 直接交给执行器。

输出保留每次 run、case、原始轨迹与判定证据的关联；报告区分攻击成功、检测命中、正常任务完成、误拒绝、执行错误。现有 envelope 来源保持 `003`；SOC 原始结果仍为 `001`，聚合报告通过关联字段连接，不重写来源。

## 4. 待实现的 SOC 轨迹桥接（A1）

在产品层增加最小事件适配器；新增文件名在实施计划中确认，禁止假装接口已经存在。

建议内部事件字段：schema_version、run_id、case_id、event_id、sequence、timestamp、actor、event_type、tool_name、decision、outcome、evidence_ref。敏感原文默认不复制到分析事件；保留受控证据引用。字段名称是提案，在编码前用 fixture 锁定。

适配器先支持三个经过明确映射的场景：越权工具调用尝试、超出配置的数据访问、工具调用预算超限。每个规则有正/反样例；缺失上下文或不支持的事件应 skipped/unknown，不能自动套用 SSH 规则。规则判定是 detector，不能作为自身攻击成功 oracle。

集成流程：runner 产生轨迹 → 白名单字段转换 → SOC 支持的规则路径 → 带证据关联的检测结果 → 原报告附加分析区。SOC 失败不能丢失基准执行结果，必须显示该阶段失败。

## 5. 指标与质量

ASR 的分母只包含预先定义的可评估攻击样例；排除/失败数量独立报告。正常任务效用与误拒绝率同时展示，不能以拒绝所有输入制造“安全提升”。检测 TPR/FNR/FPR 与攻击是否成功分别计算；judge 一致性与人工抽查报告样本范围。

固定数据集版本、配置、目标版本、模型版本（若有）、种子、超时、判定逻辑。模型判定不可确定时保留 unknown，不强行变为通过。基准从现有 task_suites/测试扩展，不凭空写覆盖率或安全性百分比。

## 6. 权限、隔离与数据

- 认证失败与跨租户资源访问均应拒绝；任务、报告、制品、取消操作都要验证所有者。
- 任务状态、重试/租约、幂等性与持久化按现有 jobs/storage 实现改进；不新建第二套任务库。
- sandbox.py 明确为 best-effort Python 子进程约束，不是生产沙箱。环境白名单、临时目录、超时有价值，但不保证内核隔离和后代进程完整终止。
- 生产执行隔离在 A2 单独完成：无宿主凭据、默认禁外网、非特权用户、只读根、受限可写制品目录、资源限额与进程树回收。实现选型须写 ADR，并有宿主文件/网络/资源逃逸负例；未通过不得开放不可信代码服务。
- 证据/提示词按配置保留与脱敏，报告默认不展示密钥和敏感内容；保留期限与清理策略应可验证。

## 7. 故障与可观测性

区分目标不可达、攻击未成功、检测未命中、judge 无法判定、工具缺失、超时和内部错误。记录 run/case/stage 标识、耗时和版本，敏感正文不进入常规日志。partial 报告显示已完成与未执行阶段，不能展示笼统“安全”。

## 8. 验收与发布门槛

历史基线：Lab 385、SOC 286 项 Python 测试通过，详见 [公共验证说明](../../docs/VALIDATION.md)，不代表本轮新功能已验收。

A0：现场权限回归；A1：确定性轨迹映射正反例、顺序/去重、证据保真、SOC 失败保留主报告；A2：隔离部署的负例证据；A3：版本化基准、安装/备份/恢复演练和试用报告。

本地 preview 可先交付受控 fixture 和评估结果。对外托管前，必须完成 A2 和生产身份/存储验证，不以单元测试代替。

## 9. 计划与文档

2026-09-30 R1/R4：负责人明确确认[实施前审查§3/§4](oidc-r1-r4-review-20260930.md)后，最小修复与本机L1验收完成，见[本轮验收报告](oidc-r1-r4-acceptance-20260930.md)。OIDC（含组合OIDC分支）必需iat/exp为非负JSON整数，排除布尔/小数/字符串/null/容器；nbf可选，存在时同类型且nbf<exp。签名等验证后强制0<exp-iat≤600秒；默认30秒容差仅用于生效/过期，直接构造器既有0～300秒容差范围保持兼容，均不扩大寿命。单public PEM启动解析：RSA≥2048匹配RS256/384/512，P-256/P-384/P-521分别匹配ES256/384/512，Ed25519/Ed448匹配EdDSA；算法列表每项均须匹配。垃圾、私钥、证书、对称材料、类型/曲线错配或读取失败使OIDC/组合模式在DB/schema/制品变更前启动失败；不回落弱认证。非OIDC与API-key原有效期策略不变。外部IdP需另设600秒签发TTL，未声称已配置；单钥切换仍维护停流、全部实例重启，无双钥/JWKS。250项现场回归通过，严格类型/Lint通过；30秒任务授权停止独立另案，19项真实部署验收仍未执行。

执行任务见 [TODO](TODO.md)，跨项目顺序见 [模型交接](../../docs/MODEL-HANDOFF.md)。原 commercial-spec、threat-model 与 ADR 提供设计背景；与本规范冲突的旧当前状态须按现场证据修正，不能直接删掉历史。
