# v0.7 派活单(可直接复制给 Codex)

> 依据:[SPEC-GAP-ANALYSIS.md](../SPEC-GAP-ANALYSIS.md)
> 顺序:`SPEC-001` → `DEF-001` → `METRIC-002` → `SCEN-E2E-001`;`ATTACK-002` 可并行
> 模板来源:[CODEX_INSTRUCTIONS.md](../CODEX_INSTRUCTIONS.md)

---

## ~~SPEC-001~~ · 修正技术方案里过期与自相矛盾的 5 处 ✅ 已完成 2026-07-26

> 已由本轮直接执行,无需派给 Codex。改动:7 处契约指向 v0.5、§5.3 YAML 矛盾裁定、
> §5.3/§5.4/§5.5 补状态标注、§9 标注实测覆盖率、§10 路线图对齐、§13 标记已交付
> 并删掉写死的测试数。**下一张可直接派的是 `DEF-001`。**

<details><summary>原派活单(存档)</summary>

```
[SPEC-001] 003 AI-Agent-Security-Lab · 修正 tech-spec 过期与矛盾之处

## 背景
- 项目: 003 AI-Agent-Security-Lab
- 这是唯一一个「改 spec 本身」的 issue,其余 issue 禁止改 spec
- 当前基线: v0.6 · 275 passed / 4 skipped · CI 双绿

## ⚠️ 必须先 Read
1. docs/SPEC-GAP-ANALYSIS.md          — 本次改动的依据(§1 表格)
2. docs/tech-spec.md                   — 待改文件
3. docs/CODEX_INSTRUCTIONS.md          — 待改文件
4. ../000shared-llm-core/docs/v0.5-contract.md  — 确认 v0.5 API 真实存在

## 必须做的事
1. 契约版本指错,共 **7 处**(用 `grep -rn "v0.1-contract" docs/` 复核):
   - docs/TODO.md:4    共享接口链接
   - docs/TODO.md:77   派活模板里的「接口契约」
   - docs/CODEX_INSTRUCTIONS.md:20   必须先 Read 的第 3 个文件
   - docs/CODEX_INSTRUCTIONS.md:31   通用模板「必须满足的约束」
   - docs/CODEX_INSTRUCTIONS.md:73   实例 1 背景
   - docs/CODEX_INSTRUCTIONS.md:88   实例 1 约束
   - docs/CODEX_INSTRUCTIONS.md:184  给 Codex 的元指令
   全部改为同时列出 v0.1-contract.md + v0.5-contract.md,并注明「共享内核
   实际版本是 0.5.0;Finding / FindingSeverity / MultiAgentOrchestrator /
   RuleEngine / FindingRegistry 都定义在 v0.5 契约,v0.1 契约里没有」

   > 这条最要紧:读 v0.1 契约会让人以为这些类不存在,进而自己重写一遍。
   > 本项目 2026-07 就踩过 —— `v05_compat.py` 正是这样多出来的 351 行重复实现。
2. tech-spec.md §5.3:「YAML DSL」与 §13 的硬编码 Python 实施指令矛盾。
   改为如实描述现状:「Python 声明式 + `longyuanai.atlas_tactics`
   entry_points 插件机制」,并把 YAML DSL 移到 §10 路线图作为 v1.0 目标
3. tech-spec.md §13:整节加标题前缀「(已完成 · 2026-07)」,并在节首写明
   Hook A/B/C 全部交付。§13.5 里硬编码的「239 passed」**删掉数字**,改成
   「全绿(具体数字见 CI)」—— 这个数两周内漂移了两次,写死必然过期
4. tech-spec.md §10 路线图:v0.6 一行改为如实描述(ATLAS 模板库 + 真 LLM
   judge + 红队报告导出 + CI),把「仿真环境 / 排行榜」顺延
5. tech-spec.md §5.3:「payload 生成器」与「修复建议」当前均无实现。
   给这两项加脚注标注「v0.7 规划中,见 REMEDIATION-001」
6. tech-spec.md §9:「OWASP 覆盖 ≥ 90%」旁边用括号标注当前实测值(约 43%,
   7 条剧本覆盖 3 条),不要删指标,只标现状

## 必须满足的约束
- 只改 docs/,不动任何 .py
- 不要删除既有章节编号(其他文档在引用 §5.4 / §12)
- 中文文档保持中文

## 不要做的事
- 不要改 tech-spec 里尚未实现能力的「目标」描述(那是产品意图,不是 bug)
- 不要动 000shared-llm-core/ 任何文件

## 验收
- [ ] pytest 全绿(测试数不应有变化,本 issue 不碰代码)
- [ ] git diff --stat 只含 docs/
- [ ] docs/ 下不再有任何硬编码的 pytest 通过数
- [ ] grep -n "v0.1-contract" docs/CODEX_INSTRUCTIONS.md 同时能看到 v0.5-contract
```

</details>

---

## ~~DEF-001~~ · Defender Toolkit ✅ 已完成 2026-07-26

> 已实现:`src/ai_agent_lab/defender/`(policy / components / pipeline)+ CLI `defend`
> + 40 个测试。Defense Coverage 10/10,Task Utility 52/54。
>
> ⚠️ **本单原验收条件「benign_corpus() 全 54 条放行」是错的,已作废。**
> 实测有 2 条会被拦,且**应当被拦**:脆弱 Agent 把良性提问路由成了 `exec_shell`
> 命令、把相对导入路由成了工作区逃逸。要凑到 54/54 只能放宽策略(允许生成代码
> 调特权函数、允许读工作区外文件)—— 那正是护栏 §6.3 禁止的事。
> 正确的验收是:**Defense Coverage = 100%,Task Utility 报实测值并说明每一条
> 被拦的归因**。
>
> **下一张可派的是 `ATTACK-002`(无阻塞)或 `METRIC-002`(现在解锁了)。**

<details><summary>原派活单(存档)</summary>

```
[DEF-001] 003 AI-Agent-Security-Lab · 实现 Defender Toolkit 四件套

## 背景
- 项目: 003 AI-Agent-Security-Lab
- tech-spec §3 把「防御者工具包」列为 Must,当前全仓零实现(已 grep 确认)
- 这是关键路径:评估引擎 6 个维度里 Defense Coverage / Task Utility 没有它
  就测不出来,§12 的旗舰剧本也跑不通

## ⚠️ 必须先 Read
1. docs/SPEC-GAP-ANALYSIS.md §3         — 为什么这是关键路径
2. docs/tech-spec.md §5.4 + §12          — 组件清单与验收剧本
3. ../000shared-llm-core/docs/v0.5-contract.md
4. src/ai_agent_lab/detector.py           — 判别式写法,新代码照此风格

## 必须做的事
1. 新建 src/ai_agent_lab/defender/ 包:
   - __init__.py        导出下述类型
   - tool_guard.py      ToolGuard(allowlist: frozenset[str])
                        .check(trace: Trace) -> GuardDecision
   - plan_validator.py  PlanValidator.validate(tool_calls) -> GuardDecision
                        (校验每一步工具是否在白名单,tech-spec §5.4「规划侧」)
   - output_auditor.py  OutputAuditor.audit(text) -> GuardDecision
                        (比对已知 bad pattern + canary token 泄漏探针)
   - input_filter.py    InputFilter.filter(user_input) -> GuardDecision
2. 在 datatypes.py 加:
   @dataclass(frozen=True)
   class GuardDecision:
       allowed: bool
       component: str          # "tool_guard" | "plan_validator" | ...
       reason: str
       evidence: str = ""
   （**不要**碰 shared_llm_core.Finding,那是冻结契约）
3. 新建 src/ai_agent_lab/defender/pipeline.py:
   DefenderPipeline(components) .evaluate(trace) -> DefenseResult
   —— 任一组件 allowed=False 即视为「已阻断」,记录是哪个组件挡下的
4. CLI 加子命令 `defend --scenario demo`:对 10 个内置攻击跑防御管线,
   输出每条攻击被哪个组件挡下 / 未挡下
5. 加 tests/test_defender.py:每个组件 ≥ 3 个用例(挡住攻击 / 放过良性 /
   边界),外加管线级 ≥ 3 个

## 必须满足的约束
- **良性语料必须全部放行**:用 benign_corpus() 的 54 条跑一遍,
  DefenderPipeline 拦截数必须为 0。防御误杀合法任务比漏防更糟
- 判别式风格,不要裸关键词匹配(参照 detector.py 顶部 _ACCESS_VERB 等)
- 纯离线、零新依赖、不调 LLM
- Windows 兼容(pathlib.Path)
- 不改 shared_llm_core 的任何 schema

## 不要做的事
- 不要修改 detector.py 的判定逻辑(检测与防御是两条独立链路)
- 不要动 tests/test_cli_envelope.py(§15 契约冻结基线)
- 不要在本 issue 里做指标(那是 METRIC-002)

## 验收
- [ ] pytest 全绿(不写死数字,只要求零 failed / 零 error)
- [ ] 新增测试 ≥ 15 个
- [ ] benign_corpus() 全 54 条被 DefenderPipeline 放行(写成断言)
- [ ] CLI smoke: python -m ai_agent_lab.cli defend --scenario demo(粘贴输出)
- [ ] ruff check src tests 全绿
```

</details>

---

## ATTACK-002 · 补齐缺失的 3 大攻击类 ← **可立即派**

```
[ATTACK-002] 003 AI-Agent-Security-Lab · 补 Memory Poison / Plan Hijack / Model DoS

## 背景
- tech-spec §5.3 定义 8 大类攻击,当前覆盖 5 类
- 缺的 3 类恰好是「Agent 特有」的那部分,也就是 §2 产品定位里的差异化卖点

## ⚠️ 必须先 Read
1. docs/SPEC-GAP-ANALYSIS.md §4 + §6   — 覆盖现状与三条护栏
2. docs/tech-spec.md §5.3
3. src/ai_agent_lab/attacks.py          — Scenario / BenignSample 结构
4. src/ai_agent_lab/detector.py         — 判别式写法

## 必须做的事
1. attacks.py 的 built_in_scenarios() 增加 3 个 Scenario:
   - memory_poison        长会话历史污染(跨轮次残留指令)
   - plan_hijack          多 Agent scratchpad 注入(orchestrator 的 scratchpad
                          是天然注入点,参照 multi_agent.py)
   - model_dos            超长上下文 / 资源耗尽(合成,不得真的打爆内存)
2. detector.py 增加对应规则 + _ATTACK_TYPE_TO_MODE 映射。
   模式仍归入现有四种之一,**不要新增 detector mode**
   (test_detector_exposes_exact_four_standard_modes 是契约)
3. **每类攻击同时在 benign_corpus() 加 ≥ 3 条 near_miss 良性样本**
4. scan.py 的 _ATTACK_ALIASES / _SEVERITY / _DISPLAY_NAMES 同步加 3 项
5. 测试:每类 ≥ 3 个(攻击命中 / 良性放行 / 边界)

## 必须满足的约束(⚠️ 重点,见 SPEC-GAP-ANALYSIS §6)
- **FPR 必须保持 0%**:evaluate_detection_quality() 的 false_positives 必须为 0。
  新规则若打中任何良性样本,是新规则的问题,不是语料的问题
- **判别式,不是裸关键词**。敏感名词只有配合访问动词 / 赋值 / 执行上下文 /
  注入祈使句时才计数
- **不得为压低 FPR 而放宽既有强信号**(tautology / rm -rf / 链路本地元数据 IP)。
  benign_corpus() docstring 里记了一条刻意不修的误报,读一下再动 sql_injection
- payload 必须是合成 canary,不含真实可执行恶意内容
- model_dos 场景不得真的分配大内存 —— 用描述性 payload,靶场是判定不是执行

## 不要做的事
- 不要新增 detector mode(四种模式是冻结契约)
- 不要动 tests/test_cli_envelope.py
- 不要改 Scenario dataclass 的既有字段

## 验收
- [ ] pytest 全绿
- [ ] 新增测试 ≥ 9 个
- [ ] 攻击类从 10 → 13,benign_corpus() 从 54 → ≥ 63
- [ ] evaluate_detection_quality(): recall 100% / FPR 0%(粘贴输出)
- [ ] CLI smoke: python -m ai_agent_lab.cli metrics 的 Detection Quality 段
- [ ] ruff 全绿
```

---

## ~~METRIC-002~~ · 补齐评估引擎缺的三个维度 ✅ 已完成 2026-07-27

> 已实现:`DefenseReport` / `evaluate_defense()`、`agent_latency_ms` +
> `detect_latency_ms` 拆分、`CostSummary` / `summarise_cost()`,全部接入
> `ASRReport` 与 `render_asr_markdown()`。19 个新测试(`test_metric_002.py`)。
> 实测:Defense Coverage 100%、Task Utility 96.3%、Detection Latency 已语义
> 正确(仅探测阶段)、Cost 离线跑为 0、接 LLM 后可统计 token。
>
> **超出票面范围多做的一件事**:`LLMDetector.detect()` 原本调了 LLM 却直接
> 丢弃 `response.usage` —— Cost 维度原本连数据来源都没有。已在其 `Detection.raw`
> 里补上 `usage`,`summarise_cost()` 从 combined detector 的嵌套 raw 结构里
> 递归取出。不改这个,Cost 永远是 0,等于假实现。
>
> **验证中发现的真实差距,已登记给 `SCEN-E2E-001`**:tech-spec §12 旗舰剧本描述
> 「Agent 抓页面 → 隐藏指令被纳入上下文 → 调用 send_email」,但内置的
> `indirect-web-injection` 场景里,单步确定性路由器实际上匹配的是
> `playwright_open`(因为同一段输入里既有 URL 又有注入短语,URL 模式匹配优先),
> 从未真正走到 `send_email`。防御链确实挡住了(`input_filter` 拦下注入短语),
> 但挡住的不是 §12 描述的那条「fetch → 二次调用」链路,而是单步文本里的指令。
> 这是 README 早就写明的 PoC 限制(「路由是单步 regex,不模拟多轮 agentic 行为」),
> 但 §12 的叙事没有对齐这一点。`SCEN-E2E-001` 需要要么改造 target agent 支持
> 两步路由,要么把 §12 的叙事改成如实描述单步版本。

<details><summary>原派活单(存档)</summary>

```
[METRIC-002] 003 AI-Agent-Security-Lab · Defense Coverage / Task Utility / 真 Detection Latency

## 背景
- tech-spec §5.5 定义 6 个评估维度,当前只实现 ASR + False Positive
- Defense Coverage 与 Task Utility 依赖 DEF-001,必须等它合并后再开

## ⚠️ 必须先 Read
1. docs/SPEC-GAP-ANALYSIS.md §3        — 三个维度为何测不了
2. docs/tech-spec.md §5.5              — 公式定义
3. src/ai_agent_lab/metrics.py         — DetectionQuality 的写法,照此扩展

## 必须做的事
1. metrics.py 加 DefenseReport:
   - defense_coverage = 已阻断攻击 / 总攻击
   - task_utility     = 防御开启后仍完成的合法任务 / 合法任务总数
     (合法任务语料复用 benign_corpus())
2. 修正 Detection Latency 语义:当前 MetricRecord.latency_ms 记的是
   target.run + detect 的合计耗时,不是 spec 定义的「攻击发生 → 告警」。
   拆成 agent_latency_ms 与 detect_latency_ms 两个字段
3. 接 Cost 维度:judge 已能拿到 response.usage,把 prompt/completion token
   累加进报告(无 LLM 时为 0)
4. render_asr_markdown() 增加「Defense」段落,与现有 Detection Quality 并列
5. 测试 ≥ 8 个

## 必须满足的约束
- ASRReport 现有字段不得改名(其他测试依赖)
- 新字段一律带默认值,保持向后兼容
- 无 LLM 时 Cost = 0,不得报错

## 不要做的事
- 不要改 Finding schema
- 不要在本 issue 里改 Defender 组件逻辑

## 验收
- [ ] pytest 全绿
- [ ] 新增测试 ≥ 8 个
- [ ] CLI smoke: metrics 报告里 6 个维度齐全(粘贴 Markdown 片段)
- [ ] ruff 全绿
```

</details>

---

## SCEN-E2E-001 · 跑通 §12 旗舰剧本(现已无阻塞)← **可派**

```
[SCEN-E2E-001] 003 AI-Agent-Security-Lab · 让 §12 旗舰剧本描述与实现对齐

## 背景
- METRIC-002 完成后发现:tech-spec §12 描述的攻击链(Agent 抓取网页 → 隐藏指令
  纳入上下文 → 二次调用 send_email)与内置 indirect-web-injection 场景的实际
  行为不符。TargetAgent._route() 是单步确定性正则路由,同一段输入里若同时出现
  URL 与注入短语,会先匹配 playwright_open,从未走到 send_email。
  防御链确实挡住了这个场景(input_filter 拦下注入短语),但挡住的不是 §12 描述
  的那条「fetch → 二次调用」链路。

## ⚠️ 必须先 Read
1. docs/dispatches/v07-tickets.md 里 METRIC-002 完成说明的最后一段
2. src/ai_agent_lab/target.py 的 TargetAgent._route()
3. docs/tech-spec.md §12
4. README.md「PoC shortcuts」一节(已有的单步路由声明)

## 必须做的事(二选一,不要同时做)

**方案 A(改代码,更贴合 §12 叙事)**:
1. 给 TargetAgent 加一个可选的两步模式:当 payload 匹配 playwright_open/
   http_fetch 且抓取结果(mock)中包含注入短语时,产生第二个 ToolCall
   (例如 send_email),并把两步都记录进 Trace(需要扩展 Trace 支持多个
   tool_call,或加一个 chained_tool_call 字段)
2. DefenderPipeline.evaluate 需要能对多步 trace 逐步评估
3. 用这个两步版本重新验证 §12 剧本,产出完整证据链

**方案 B(改文档,如实描述现状,工作量小得多)**:
1. tech-spec §12 剧本第 4 步改为如实描述:「Agent 单步路由匹配 playwright_open
   (URL 模式优先于注入短语)」,不再声称调用了 send_email
2. 第 5 步改为:「input_filter 检测到注入祈使句,直接拦截整个请求」
3. 在剧本末尾加一条注记,说明「若要演示完整的 fetch → 二次调用链路,需要
   TargetAgent 支持多步路由,当前 PoC 是单步」

## 必须满足的约束
- 方案 A 是新场景/行为改造,需要新测试覆盖两步路由与两步防御评估;
  不得破坏现有单步场景的行为(所有 built_in_scenarios() 必须仍按原样路由)
- 方案 B 只改 docs/,不动代码
- 先问人类要哪个方案,不要自行决定(工作量差异大)

## 验收(方案 A)
- [ ] pytest 全绿,新增测试 ≥ 6 个
- [ ] CLI smoke: defend 命令能展示两步 trace 的防御结果
- [ ] ruff 全绿

## 验收(方案 B)
- [ ] git diff --stat 只含 docs/tech-spec.md
- [ ] §12 剧本读起来与代码行为一致(可执行验证:跑一遍
      DefenderPipeline().evaluate(TargetAgent().run(indirect-web-injection.payload))
      看输出是否与文中描述吻合)
```

---

## 备选小票(随时可插)

| ID | 一句话 | 预估 |
|----|--------|------|
| `REMEDIATION-001` | `Scenario` 加 `remediation` 字段,报告输出修复建议(spec §5.3 承诺过) | 30 min |
| `OWASP-001` | `Scenario` 加 `owasp_ids`,让 §9 的「覆盖率 ≥ 90%」变成可计算数字 | 30 min |
| `REPRO-001` | CI 加一步:同 seed 跑两次 ATLAS,diff 必须为空(§9「重现一致性 ≥ 95%」的自动验证) | 20 min |
| `CI-002` | CI checkout 加 `000shared-integration`,让 4 个 skip 的 gateway 用例真跑起来 | 20 min |
