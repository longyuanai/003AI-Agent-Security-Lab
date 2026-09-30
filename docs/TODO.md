# 001AI-Agent-Security-Lab 开发任务

建立日期：2026-09-23；A0 更新：2026-09-27；部署权限计划更新：2026-09-28。各任务状态以对应现场证据为准；历史已有功能见 tech-spec，不把旧 TODO 的完成状态机械搬来。

每轮只做一个有验收边界的任务，建议 Code 首轮组合 C0 与 C1。任务完成后填写证据、日期和提交，不仅打勾。

[本项目技术规范](tech-spec.md) · [全局交接指南](../../docs/MODEL-HANDOFF.md)

## A0 — 复核现有基线与权限改动

- 状态：已完成（2026-09-27，本机现有权限与跨租户基线；不代表生产多租户验收）。
- 工作：读取现有 dirty diff 与 tenant 测试；确认 run/任务/制品的授权路径，记录当前通过与未验证项。
- 验收：不丢弃现有修改；现场相关权限与跨租户负例通过；未验证生产条件明确。
- 依赖与范围：无；只读基线优先。
- 现场证据：[A0 授权路径与验收报告](a0-authorization-baseline-20260927.md)。根 HEAD `4235350`、Agent HEAD `74fbe58`，既有源码与 `tests/test_tenant_isolation.py` 保持原字节；未提交。原有七文件现场基线 100 passed；新增 56 个负例后联合运行 156 passed / 0 failed / 0 skipped，exit 0。覆盖六操作未认证/撤销/篡改、HTTP 与服务 RBAC、缺失/停用租户、伪造租户输入、worker 中途停用清理和跨租户 claim。未复现需修改产品的权限缺陷。
- 检查：新测试 Ruff exit 0、git diff --check exit 0；mypy 最初缺失，已将固定 1.20.2 安装到独立 TEMP 目录，仅用作开发检查、不改生产依赖。配置 MYPYPATH 并修正新测试的一处内部导入引用后，strict mypy exit 0（新测试 1 文件）；再跑相关 pytest 156 passed，exit 0。首次断言/工具/类型失败及最终日志均保留。
- 后续：部署权限计划与材料已于2026-09-28准备，见下一节；A0本机证据不覆盖真实IdP、PostgreSQL多实例或生产执行隔离。

## A0 后续 — 部署权限验证计划与材料

- 计划与材料：已完成（2026-09-28）；**真实部署验收：未执行、未通过**。交付 [部署权限验证计划](deployment-authorization-validation-plan.md)，19项矩阵包含前置/操作/预期/证据/清理，并独立列出A2边界。
- 本轮改动：新增离线材料脚本、JSON/env参考模板、合成账号与资源别名、not_run证据模板及12个本地测试；不修改产品源码、认证架构、冻结接口或生产依赖。未部署、未创建外部资源、未连接PG/真实IdP，不推进A1/A2。
- 本轮验证：新增文件pytest最终12 passed / 0 failed / 0 skipped，exit0；strict mypy两文件、Ruff和链接只读检查exit0。prepare/check/cleanup-plan分别exit0/4/0；4明确表示真实部署未验证，cleanup只预览且删除0。详细命令及所有初次失败见计划§9与 `docs/evidence/deployment-plan-20260928/`，不引用A0历史通过数作为本轮结果。
- 复核发现：静态公钥仅启动加载（DEP-AUTH-01）、旧角色token不即时失效（DEP-AUTH-02）、拒绝日志缺actor/tenant关联（DEP-AUTH-03）、常驻worker入口尚未提供（DEP-MULTI-01）。前两项先定SLA；完整身份审计缺口另列最小修复，未在本轮修改产品。
- 仍缺：真实测试IdP及映射/轮换决策、专用PG与恢复目标、API/worker多实例拓扑和共享制品ACL、可信日志关联/保留策略、运行与清理负责人。缺前置时真实用例记not_run/blocked，不以mock结果替代。
- 下一项最小任务：先评审16项非秘密决策，确定角色失效SLA、公钥切换窗口和审计归因要求；然后独立处理DEP-AUTH-03。真实环境执行需另次明确授权与准入检查，不能把材料完成标为部署通过。
- 决策评审材料：已完成（2026-09-29）。见 [部署权限环境决策评审](deployment-authorization-decisions.md)：16项决策表、推荐组合（全部为建议，**未经负责人批准**）、三个关键决策、19项验收映射（W 6、W部分 3、F 9、B 1）和缺口 G1～G8；本轮未改源码/脚本，未运行测试。**19项真实部署验收仍未执行。** 待负责人回答文中 §9 的3个问题；之后下一项为 G1+G4（DEP-AUTH-03 审计归因）。
- 负责人决定（2026-09-29）：§9 三问均选 A（失效上限：TTL 10 分钟+30 秒，不做即时撤销；公钥：15 分钟维护窗口、全部实例重启；审计：HMAC 主体/租户哈希 + 服务端 request ID + run 明文提交者）。其余决策仍为建议。

- 2026-09-30再次评审：已按当前源码更新 [决策文档§11～§18](deployment-authorization-decisions.md#11-2026-09-30-当前代码复核与16项推荐)。保留9月29日既有审批/实现记录；本轮新增或调整推荐全部**待确认**，**19项真实部署验收仍未执行**。16个原模板键、19项验收的环境/代码阻塞和顺序均有逐项对应。当前G1/G4已实现，不能再列为尚缺；源码迁移head是0005，不推定实际数据库已应用。
- 本轮推荐重点：TTL10分钟且产品强制600秒一致上限（旧15分钟产品上限不满足10.5分钟目标）；租户在途授权停止30秒是R3/G5待实现目标，300秒租约不保证停止时限；单钥维护窗不支持在线并存/JWKS；审计现有HMAC归因还需身份域、worker标签、ACL/保留与完整性验证。新增R1～R5及既有G5～G8只列任务，不改源码。
- 本轮范围与验证：只更新决策文档/TODO并保存备份、摘要和文档检查记录；不新增脚本、不安装依赖、不运行权限测试、不部署、不提交。文档引用/16键/19验收及git diff --check现场结果见 `docs/evidence/deployment-decisions-20260930/checks.json`。
- 文档检查结果（2026-09-30）：16键/19项一致，全部部署状态未执行，24个本地引用和新章节锚点有效；PowerShell文档检查、git diff --check、只读repair_links均exit0。首次证据文件自引用检查失败已保留并复查；不是产品失败。除决策文档与本TODO外既有文件摘要无变化。
- 当前进度更新：负责人本轮仅明确确认审查报告§3/§4的R1/R4，修复验收见下方独立条目；其他新增推荐仍待确认，R3/G5另案。环境仍需逐项提供和授权，任何推荐不自动转成部署通过。

## G1+G4 — 审计主体归因（DEP-AUTH-03）与 run 提交者

当前R1/R4进度（2026-09-30）见下一独立条目；本节G1/G4与其测试数字仍为9月29日历史，不计作R1/R4本轮结果。

- 状态：本机实现与 L1 测试完成（2026-09-29）；**未部署、未提交；AUDIT-01/02 的 D 级验收仍未执行。** 行为与兼容变化见 [决策评审 §8.1](deployment-authorization-decisions.md)。
- 修改：`api/app.py`、`api/server.py`、`observability.py`、`application/service.py`、`application/authorized.py`、`domain/runs.py`、`storage/models.py`、`storage/run_repository.py`；新增 `migrations/versions/0005_run_created_by.py`、`tests/test_audit_attribution.py`（12 例）。README 和 env 参考模板新增 `LAB_AUDIT_HASH_KEY`/`LAB_INSTANCE_ID`。修改前的文件（含已有未提交改动）备份在 `docs/evidence/g1-g4-20260929/before/`，并附 SHA-256。
- 现有测试最小调整：`test_api_v1.py` 中原“客户端 request ID 原样保留”的用例改为“服务端 ID + `X-Client-Request-Id` 回显”（负责人 Q3=A 批准的行为变化）；`test_auth.py` 的 api_key 服务端用例与 `test_deployment_authorization_materials.py` 的公钥轮换用例补充了合成审计密钥。断言没有放宽。
- 基线（改动前）：10 个相关文件 176 passed / 1 failed。失败的是 `test_a0_authorization.py::test_denied_request_does_not_log_bearer_secret`，与执行顺序有关：`migrations/env.py` 的 `fileConfig` 会禁用已经创建的 logger，而该文件单独运行时 56 passed。按排除法定位到与 `test_storage.py` 的 Alembic 用例同跑时触发。这是既有测试隔离问题，不是权限缺陷，已单列后续任务，本轮不修改。
- 结果：新测试首次运行 2 failed（测试自身问题：幂等键短于 8 位；API key 在租户停用后按 A0 行为返回 401），修正测试后 12 passed。同样 10 个文件加新文件共 188 passed / 1 failed，失败仍是上面那个顺序问题，该用例与 tenant 测试单独运行 67 passed。全量 `tests/`（PYTHONPATH 加入 000shared-integration）最终 **465 passed / 0 failed**，exit 0。未加该路径时 `test_cli_envelope` 子进程找不到模块，属于环境问题，补上路径后 8 passed。
- 静态检查：strict mypy 1.20.2（安装在独立 TEMP 目录，仅供开发检查）对改动的 10 个文件报 18 个错误，与原版本在临时镜像中得到的 18 个完全相同，均为既有问题；新文件及无既有问题的文件 exit 0。Ruff：新文件和 service/authorized/runs exit 0；其余被改文件的计数与原版本相同（修掉了本轮引入的 1 处 UP012）。`git diff --check` 结果见最终报告。
- 下一项：负责人复核后可提交本轮差异（只提交本轮文件/差异块）；部署前 AUDIT-02 须在真实环境用两个测试账号复测。后续修复顺序 G7 → G5 → G6 → G8，G3 需要另行授权。

## R1/R4 — 令牌寿命与静态公钥启动校验

- 状态：负责人已明确确认审查报告§3/§4；**R1/R4最小源码修复及本机L1验收完成（2026-09-30），未部署、未提交**。见 [本轮修复验收](oidc-r1-r4-acceptance-20260930.md)；[实施前审查](oidc-r1-r4-review-20260930.md)保留历史观察，不作为修复通过证据。
- 行为：OIDC及组合OIDC分支要求非负JSON整数iat/exp，nbf可选但同类型且nbf<exp；0<exp-iat≤600秒，默认30秒容差不扩大寿命。单public PEM启动解析，每个算法均匹配RSA≥2048、对应EC曲线或Ed25519/Ed448；配置错误在数据库/制品创建前失败，无弱认证回落。
- 兼容：拒绝过去宽松接受的超长/零负寿命和字符串、小数、布尔时间；非OIDC忽略未使用公钥，API-key原有效期与撤销策略保持不变；外部IdP签发TTL仍需真实环境设置。
- 本轮现场验证：95项新安全行为断言与155项现有回归联合250 passed / 0 failed / 0 skipped，exit0；严格mypy涉及3文件、Ruff、引用/保护摘要与git diff --check均通过。实际命令、独立basetemp、初次静态失败和最终日志见验收报告及 `docs/evidence/r1-r4-fix-20260930/`，不引用历史通过数。
- 范围：仅auth.py/server.py最小改动、新增正式测试、技术规范/TODO和本轮证据；已有权限、存储及tenant测试原字节保护。生产依赖、公共契约和其他产品不变。**19项真实部署验收全部未执行**。
- 下一项：独立复核R3/G5的30秒租户授权停止与运行中任务停止边界，先明确触发、检查点、取消和制品语义；本轮未实现。公钥切换仍维护停流、全部实例重启，不增加双钥/JWKS。真实部署须另获授权并补足IdP、专用PG和多实例设施。

## A1 — SOC 轨迹桥接

- 状态：待执行。
- 工作：在 Agent 添加最小轨迹适配、受支持规则和报告附加；必要时改 SOC 模块公共规则入口。
- 验收：三个受支持场景正反例、证据关联、顺序/去重、缺字段、SOC 失败不丢主结果；oracle 与 detector 分离。
- 依赖与范围：A0；仅 Agent + SOC 两仓。
- 完成证据：待填写实际命令、结果、未验证项与提交。

## A2 — 生产执行隔离验证

- 状态：待执行。
- 工作：先 ADR 明确目标运行环境，再实施资源/网络/文件隔离、取消与进程回收。
- 验收：真实运行环境的越界/网络/资源/子进程负例及审计；未部署部分明确标注；不开放不可信执行服务。
- 依赖与范围：A0；独立于 A1，可排期但不得凭单测宣布完成。
- 完成证据：待填写实际命令、结果、未验证项与提交。

## A3 — 可复现评估交付

- 状态：待执行。
- 工作：版本化基准、任务效用/误拒绝/检测指标、试用文档与恢复说明。
- 验收：固定样本复跑、人工抽查、报告复现；若托管则 A2 和生产权限验收先通过。
- 依赖与范围：A1；托管形态另需 A2。
- 完成证据：待填写实际命令、结果、未验证项与提交。

## 通用停止条件

范围超出任务、需要新技术栈/冻结接口破坏性改动、外部部署环境缺失时，先完成可独立验证部分并报告具体条件。不得删除测试、降低权限或伪造验证来满足验收。

原技术规范和旧任务清单保存在 docs/archive/2026-09-23-pre-consolidation；历史计划用于追溯，不自动执行。

## 并入记录（2026-09-30 合并 origin/master 时保留）：工程健康度整改与 v0.7 交付（来自 `claude/project-issues-optimization-o1deze`）

> 以下条目由 2026-07 的整改分支交付，已在本次整合中并入代码库；保留原记录以便追溯。

### P0 · 工程健康度整改(2026-07-26,见 AUDIT/003-S2.md)

| ID | 任务 | 状态 | 完成日 | 备注 |
|----|------|------|-------|------|
| FIX-PKG-001 | 修复 pyproject,让 `pip install -e .` 能装上 | done | 2026-07-26 | `[project]` 缺 name,poetry-core 直接拒绝;曾导致 23 个测试文件全部无法收集 |
| FIX-IMPORT-001 | `__init__.py` 改惰性导出,离线核心零依赖可用 | done | 2026-07-26 | PEP 562 `__getattr__` |
| FIX-DUP-001 | 删除 `v05_compat.py`,统一到 shared-llm-core | done | 2026-07-26 | 共享库早已是 v0.5.0,该模块 351 行全是重复;顺带修好 MCP demo 角色错配 |
| FIX-CI-001 | 接入 GitHub Actions (pytest + ruff × 3.11/3.12) | done | 2026-07-26 | 之前完全没有 CI |
| FIX-FPR-001 | 良性语料 + 误报率/精确率/F1 | done | 2026-07-26 | 原检测器 7/7 良性输入误报,"100% 检出率"不可证伪 |
| FIX-REPRO-001 | `--seed` 让 ATLAS 报告可复现 | done | 2026-07-26 | 报告中标注能否复现 |
| CORPUS-001 | 良性语料扩到 54 条 | done | 2026-07-26 | 暴露并修好 3 条新误报 + 1 处漏报(敏感数据外传非 evil.example.com 时只判 suspicious) |
| JUDGE-002 | LLM judge 容错 | done | 2026-07-26 | 畸形 LLM 输出(confidence 越界/非数字、散文、JSON 后跟尾句)会直接抛异常;8 个探针 5 个崩。真接 LLM 时可能整轮全是 error。已改为降级为 suspicious,传输错误仍上抛 |
| SAND-003 | 补齐沙箱声称范围内的逃逸口 | done | 2026-07-26 | `os.replace/rename/shutil.move` 曾能把文件搬出沙箱(实测逃逸成功);`_socket` 绕过网络守卫。两处已修,`subprocess`/`ctypes` 两个够不着的口子用测试钉住 |

#### v0.7 派活(2026-07-26 拟)

差距分析: [SPEC-GAP-ANALYSIS.md](SPEC-GAP-ANALYSIS.md) · 可直接复制的派活单: [dispatches/v07-tickets.md](dispatches/v07-tickets.md)

| ID | 任务 | 优先级 | 依赖 |
|----|------|--------|------|
| ~~SPEC-001~~ | 修正 tech-spec 过期/矛盾 | ✅ done 2026-07-26 | 已直接执行,不必派 Codex |
| ~~DEF-001~~ | Defender Toolkit 四件套 | ✅ done 2026-07-26 | Coverage 10/10 · Task Utility 52/54 · CLI `defend` · 40 测试。**推翻了「工具名白名单即可」的假设**,详见 tech-spec §5.4 |
| ~~ATTACK-002~~ | 补 Memory Poison / Plan Hijack / Model DoS 三大攻击类 | ✅ done 2026-07-28 | 攻击面 5/8 → 8/8。13 个新测试。**顺带发现并修复一个真实的 Defense Coverage 回归**:`model_dos` 请求常常不产生工具调用,`ToolGuard`/`PlanValidator` 无从检查,已扩展 `InputFilter` 直接在 `user_input` 上判定无界生成,详见 tech-spec §5.4 |
| ~~METRIC-002~~ | Defense Coverage / Task Utility / 真 Detection Latency / Cost | ✅ done 2026-07-27 | 六维度全接入 `ASRReport`;顺带发现 §12 剧本第 4-5 步叙事与单步路由器实现不符,已登记给 `SCEN-E2E-001` |
| SCEN-E2E-001 | 让 §12 旗舰剧本描述与实现对齐(改路由支持两步,或改文档如实描述单步) | P1 | **无阻塞,可立即派**(需人类先选方案 A/B,见派活单) |
| REMEDIATION-001 | Scenario 加 remediation,报告输出修复建议 | P2 | 无 |
| OWASP-001 | Scenario 加 owasp_ids,让覆盖率可计算 | P2 | 现在解锁了(`ATTACK-002` 已完成) |
| REPRO-001 | CI 加「同 seed 跑两次 diff 为空」 | P2 | 无 |
| CI-002 | CI 加 checkout 000shared-integration,4 个 skip 用例真跑起来 | P2 | 无 |

> ⚠️ 派活时**必须**把 SPEC-GAP-ANALYSIS §6 的三条护栏抄进约束段:
> 新攻击类必须配良性近似样本、用判别式不用裸关键词、不得为压 FPR 削弱强信号。

---

#### 待办(未做,需排期)

| ID | 任务 | 优先级 | 说明 |
|----|------|--------|------|
| SAND-002 | 真正的内核级沙箱 (Docker + seccomp) | P1 | 声称范围内的口子已补(见 SAND-003)。剩余 `subprocess` 子进程 / `ctypes` 直调 C 是进程内 monkeypatch 原理上够不着的,已有测试钉住行为;真要挡住必须上 OS 级边界。**注**:当前威胁模型是自写的合成 payload,不是不受信任代码,所以优先级低于 DEF-001 |
| SCEN-002 | 场景改为 YAML/DSL 加载 | P2 | 现在硬编码在 `attacks.py`。注意 tech-spec §5.3 声称是 YAML DSL 而 §13 实施指令是硬编码 Python —— 方案自相矛盾,SPEC-001 会先裁定走哪条 |

---

> origin/master 同期的完整旧版技术规范存档于 [archive/2026-09-30-merged-master/tech-spec.md](archive/2026-09-30-merged-master/tech-spec.md)，仅作追溯。
