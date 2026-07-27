# 技术方案差距分析 · 派活前必读

> **日期**: 2026-07-26
> **作者**: Claude
> **用途**: 给 Codex 派 v0.7+ 任务前的 spec 审查。逐条对照 `tech-spec.md` 声称的能力与代码实际状态。
> **基线**: v0.6 · 275 passed / 4 skipped · CI 双绿

---

## 0. 结论先说

**方案本身没有方向性错误,问题在三处:**

1. ~~**有五处过期/自相矛盾,会直接误导 Codex**~~ —— **已于 2026-07-26 直接修完**(§1)。
2. **Defender Toolkit 是关键路径,不是"少一个模块"** —— 评估引擎 6 个维度里有 3 个没它就**测不出来**,§12 的旗舰剧本也跑不通(§3)。
3. **攻击面覆盖 5/8 大类**,缺的 3 类(Memory Poison / Plan Hijack / Model Theft & DoS)恰好是"Agent 特有"的那部分 —— 而这正是 §2 产品定位里写的差异化卖点(§4)。

---

## 1. 方案本身要先改的地方(✅ 已完成 2026-07-26)

这几条如果不改,Codex 读了会走错路。**本节 5 条已全部执行完毕**,下表保留作记录。

> 实际执行时发现契约指错不是 1 处而是 **7 处**(TODO.md 2 处 + CODEX_INSTRUCTIONS.md 5 处),
> 且 §5.3/§5.4/§5.5 顺带补了逐项实现状态标注 —— 让 Codex 一眼能看出哪些是「已交付」
> 哪些是「产品意图但零代码」,不必再去翻代码确认。

| # | 位置 | 问题 | 建议 |
|---|------|------|------|
| 1.1 | `CODEX_INSTRUCTIONS.md` 第 3 条 | 让 Codex 读 `000shared-llm-core/docs/v0.1-contract.md`。但本项目现在用的是 v0.5 API(`Finding` / `MultiAgentOrchestrator` / `RuleEngine`),共享仓里 **`v0.5-contract.md` 已存在**。Codex 读 v0.1 契约会以为这些类不存在,可能重新自己实现一遍 | 改为同时读 v0.1 + v0.5 契约,并注明「共享内核实际版本是 0.5.0」 |
| 1.2 | `tech-spec.md` §5.3 | 写「8 大类 30+ 攻击模式(**YAML DSL** 描述)」,但 §13 Phase-2 的实施指令是硬编码 Python(`atlas/aml_t0051.py`),现状也是硬编码。**方案自相矛盾** | 二选一并写死:要么承认现状改成「Python 声明式 + entry_points 插件」,要么把 YAML DSL 立为正式目标并单开 issue |
| 1.3 | `tech-spec.md` §13 | 整节以「Hook A/B/C 待实施」口吻写,但**三个 Hook 都已完成**(ATLAS 模板库 / 真 LLM judge / 红队报告)。§13.5 验收里硬编码了测试数「239 passed」,实际 275 —— 这个数字**两周内已经漂移两次**,说明文档里写死测试数注定过期 | 把 §13 标记为「已完成」并归档,新开 §14 承接 v0.7;§13.5 的测试数改成「全绿」,数字交给 CI 而不是文档 |
| 1.4 | `tech-spec.md` §10 路线图 | 「v0.6 GA = 仿真环境 + 排行榜 + CI 接入」。实际 v0.6 交付的是 ATLAS + judge + report;仿真环境和排行榜**一行代码都没有** | 路线图与实际对齐,否则每次复盘都在对一份假基线 |
| 1.5 | `tech-spec.md` §5.3 | 「每个模式带:触发条件、payload **生成器**、检测信号、**修复建议**」。实际 `Scenario` 只有静态 payload,**全仓没有任何 remediation 字段**(已 grep 确认) | 要么给 `Scenario` 加 `remediation` 字段(小改动,见 TASK-REMEDIATION-001),要么从 spec 删掉这个承诺 |

---

## 2. 方案 vs 代码:MoSCoW Must 对照

| §3 Must 能力 | 状态 | 实际情况 |
|---|---|---|
| 内置脆弱 Agent 集 | ✅ | 5 个 profile |
| 工具集(文件/shell/HTTP/SQL/邮件) | ⚠️ | 工具**全是 mock 字符串**(`"[mock] shell not executed"`),没有真实执行。对靶场是合理取舍,但 spec 没说明 |
| 攻击者工具包 | ⚠️ 5/8 | 见 §4 |
| **防御者工具包** | ❌ **完全没有** | 见 §3 |
| 隔离沙箱(Docker + seccomp) | ⚠️ | 仅 Python 层 monkeypatch。声称范围内的逃逸口已补齐并有测试;子进程 / `ctypes` 原理上够不着,已用测试钉住 |
| 评估引擎 | ⚠️ 2/6 | 见 §3 表 |
| 报告(攻击链可视化 / **修复建议** / 可重放) | ⚠️ | 报告 ✅、可重放 ✅(`--seed`)、**修复建议 ❌**、攻击链可视化仅 correlation 的 ASCII 树 |

---

## 3. 关键路径:Defender Toolkit(§5.4)

**这是整个方案里投入产出比最高的一块,因为它同时解锁三个指标和一个旗舰剧本。**

§5.5 的 6 个评估维度现状:

| 维度 | 状态 | 说明 |
|---|---|---|
| Attack Success Rate | ✅ | `evaluate_asr()`,50 组合 |
| False Positive | ✅ | 2026-07-26 补齐,54 条良性语料 |
| **Defense Coverage** | ❌ **测不了** | 分母是「已阻断攻击」,没有 Defender 就没有「阻断」这个动作 |
| **Task Utility** | ❌ **测不了** | 需要「合法任务」语料 + 防御开启后仍能完成的判定 |
| Detection Latency | ⚠️ 名不副实 | `MetricRecord.latency_ms` 记的是 `target.run + detect` 的**合计耗时**,不是 spec 定义的「攻击发生 → 告警」延迟 |
| Cost | ❌ | 无 token / 算力统计。注:judge 已经拿得到 `usage`,接上去成本很低 |

§12 的典型剧本(方案自己给的 end-to-end 验收目标)现在**跑不出来**:

> 5. Defender Toolkit 拦截:Tool Guard 校验 send_email 不在白名单 → 阻断 + 告警
> 6. 评估:ASR=0%;Defender Coverage=100%;输出完整证据链

第 5、6 步没有任何代码支撑。**建议把 §12 剧本直接立为 Defender Toolkit 的验收标准** —— 方案里已经写好了预期输出,拿来即用。

---

## 4. 攻击面:8 大类覆盖 5 类

| §5.3 大类 | 状态 | 对应实现 |
|---|---|---|
| 1 Direct Prompt Injection | ✅ | `prompt_injection` + ATLAS AML.T0051 |
| 2 Indirect Prompt Injection | ✅ | `indirect_prompt_injection` + AML.T0054 |
| 3 Tool Escape | ✅ | `shell_escape` / `path_traversal` / `browser_ssrf` / `sql_injection` |
| 4 **Memory Poison** | ❌ | 无。长会话 / 跨会话历史污染 |
| 5 **Plan Hijack** | ❌ | 有 `multi_agent` 编排,但**没有针对它的攻击**。scratchpad 是天然的注入点 |
| 6 RAG Poison | ✅ | `rag_poisoning` |
| 7 Supply Chain | ✅ | `scenarios/supply_chain.py` + `mcp.py` |
| 8 **Model Theft / DoS** | ❌ | 无。超长上下文 / 资源耗尽 |

OWASP 标准剧本(§5.5)清单共 **10 条**(6 条 OWASP + 4 条 Agentic 扩展),实测:

- **完整覆盖 3 条**:LLM-01 Prompt Injection、LLM-08 Vector & Embedding、Agentic Tool Misuse
- **部分覆盖 2 条**:LLM-02 Sensitive Disclosure(token_theft / email_exfiltration 沾边)、LLM-06 Excessive Agency(tool_misuse 沾边)
- **未覆盖 5 条**:LLM-07 系统提示泄露、LLM-10 Model Theft、Agentic Plan Hijack、Agentic Memory Poison、Agentic Identity Spoofing

→ **严格计 3/10 = 30%;计入部分覆盖 5/10 = 50%**。

§9 定的产品指标是「OWASP 覆盖 ≥ 90%」,当前 30%(严格)/ 50%(宽松)。**已在 spec §9 如实标注**,否则指标形同虚设。

> 补充:全仓**没有任何 OWASP 编号到攻击类的映射**(已 grep 确认)。就算覆盖率上去了,也没法自动算出「覆盖了哪几条」。建议给 `Scenario` 加 `owasp_ids` 字段,让覆盖率变成可计算的数字而不是人工数。

---

## 5. 建议的派活顺序

按依赖排,前两个是关键路径:

```
SPEC-001  改 spec 自身的 5 处过期/矛盾      ✅ 已完成 2026-07-26
   │
   ├─ DEF-001   Defender Toolkit (4 个组件)   ← 解锁 3 个评估维度,可立即派
   │      └─ METRIC-002  Defense Coverage / Task Utility / 真 Detection Latency
   │             └─ SCEN-E2E-001  跑通 §12 旗舰剧本(端到端验收)
   │
   ├─ ATTACK-002  Memory Poison + Plan Hijack + Model Theft/DoS
   │      └─ OWASP-001  Scenario 加 owasp_ids,覆盖率变成可计算
   │
   └─ REMEDIATION-001  Scenario 加 remediation,报告输出修复建议
```

---

## 6. ⚠️ 派活时必须写进约束的三条护栏

这三条是 2026-07-26 那轮整改踩出来的,不写进派活单,Codex 大概率重新踩一遍。

### 6.1 每加一个攻击类,必须同时加良性近似样本

`benign_corpus()` 现有 54 条,每条标注自己模仿哪个攻击类。**这是唯一能防止检测器退化成"见人就咬"的机制。**

整改前的教训:规则从攻击 payload 反向抄出来,7 条良性输入 7 条误报(5 条判 malicious),而「100% 检出率」看起来毫无问题 —— 因为**没人测过负样本**。一个「对任何输入都返回 malicious」的检测器能拿到完全相同的分数。

> **派活单里必须写**:新增攻击类的同时,在 `benign_corpus()` 加 ≥ 3 条对应 `near_miss` 的良性近似样本;`evaluate_detection_quality()` 的 FPR 必须保持 0%。

### 6.2 判别式,不是关键词

新规则不能只匹配裸关键词。参照 `detector.py` 顶部 `_ACCESS_VERB` / `_EXEC_CONTEXT` / `_INJECT_IMPERATIVE` / `_SENSITIVE_TAIL` 的写法:**敏感名词只有在配合访问动词、赋值、执行上下文或注入祈使句时才计数**。

反例(整改前真实存在):`bash -c` 裸匹配 → "our runbook says to use bash -c" 判 malicious。

### 6.3 不要为了压误报而削弱强信号

`benign_corpus()` 的 docstring 里记了一条**刻意不修**的误报:`"Explain how OR 1=1 works in a SQL injection tutorial."` 压制它需要「解释性语境降级判决」这类规则,等于送攻击者一个 `Explain how ...` 前缀绕过。

> **派活单里必须写**:调低 FPR 不得以放宽 tautology / `rm -rf` / 链路本地元数据 IP 这类强信号为代价。

---

## 7. 其他值得进 spec 但目前完全没提的

| 项 | 为什么重要 |
|---|---|
| **成本统计** | §5.5 列了 Cost 维度,§9 没有对应指标。judge 已经拿得到 `usage`,接上去很便宜 |
| **v1.0 多模型对比** | PHASE-2 路线图写了「同一攻击对 GPT/Claude/Qwen 各自表现」,但 `LLMRuntime` 一次只能选一个 provider,没有并排跑的编排 |
| **靶场自身被反控** | §9 有「靶场本身被反控 = 0」的指标,但没有任何检测机制。至少该有一条:ATLAS payload 必须是合成 canary,不得含真实可执行恶意内容(现在靠人工守纪律) |
| **重现一致性 ≥ 95%** | §9 指标。`--seed` 已让 ATLAS 可复现,但**没有测量机制**。可以加一个「同 seed 跑两次 diff 必须为空」的 CI 步骤,把指标变成自动验证 |

---

## 8. 我不建议现在做的

| 项 | 理由 |
|---|---|
| 仿真环境(§5.7 DVWA / Mail / AD) | 投入极大,且 §5.7 自己标了「可选」。在 Defender Toolkit 之前做,等于给一个还不会防守的靶场加真实靶标 |
| 完整 K8s / 多租户部署(§8) | 当前是单机库形态,离多租户还有两个数量级的距离。PoC 阶段做这个是提前优化 |
| 排行榜(§3 Could) | 依赖多模型对比,而多模型对比依赖成本统计。链条太长,先把评估引擎补完整 |
| 内核级沙箱(SAND-002) | 优先级不低,但它挡的是「不受信任代码」场景。当前靶场跑的全是自己写的合成 payload,威胁模型对不上。等到要接客户自研 Agent 时再做 |
