# 003AI Agent安全靶场 · Phase-2 计划

> **本仓角色**: AI Agent 安全性测试靶场。注入攻击模拟(indirect prompt injection / jailbreak / tool abuse),评估目标 agent 的稳健性,产出风险 Finding。
> **当前状态**: v0.6 · Hook A/B/C 全部落地 · 243 passed / 4 skipped · ruff 全绿 · CI 已接入。
> **下一阶段**: v1.0 多模型对比 + 防御者工具包 (tech-spec §3 Must,尚未开工)。
>
> 2026-07-26 补充:完成一轮工程健康度整改,详见 [AUDIT/003-S2.md](AUDIT/003-S2.md)。
> 整改前仓库实际处于「装不上 / 测试一条都跑不起来」状态,且检测器对良性输入
> 7/7 误报,「100% 检出率」不可证伪。

---

## 进展更新(2026-10-01)

| Hook | 状态 | 实现位置 |
|------|------|----------|
| A · ATLAS 模板库 | 已实现:15 个顶层技术(含 T0051 子技术共 17 个 ID),名称与 ATLAS 官方一致并标注所属战术;每个技术至少 1 个可执行安全测试用例(共 24 个),每个技术配测试 | `src/ai_agent_lab/atlas/`、`atlas/testcases.py`、`tests/test_atlas_testcases.py` |
| B · LLM-as-judge | 已实现:经 shared-llm-core 路由(`build_lab_router`,`LAB_LLM_KEY` 显式开启),与规则判定逐例对比(一致率、Cohen's kappa、混淆矩阵、分歧列表);测试全部用 mock 路由 | `src/ai_agent_lab/redteam.py`、`tests/test_redteam_judge.py` |
| C · 红队报告导出 | 已实现:Markdown / 自包含 HTML / JSON,CLI `redteam --format md/html/json` | `src/ai_agent_lab/report/red_team_export.py`、`tests/test_red_team_export.py` |

本机实测(2026-10-01,Ollama `qwen2.5:7b`,CPU,`file_rag` 6 个用例,共 12 次调用):首轮判官只看到探针文本,对两个无工具调用的用例误判为 compromised(一致率 4/6,kappa 0.00);在判官输入中加入 `agent_output` 并要求只依据可观察行为后复测 6/6 一致(kappa 1.00)。样本很小,不能代表判官整体准确率。

仍未做:多模型对比(v1.0)、nightly CI、真实(非 mock)目标 agent 适配器、报告中 LLM 判官成本统计。

## 现状摘要(2026-07-25)

| 项 | 状态 |
|----|------|
| v0.1 LLM 集成(目标 agent + 评估 agent) | ✅ |
| v0.5 Finding schema | ✅ |
| `indirect_injection` 等基础攻击 payload | ✅ |
| `iterations` 多次迭代支持 | ✅ |
| CLI 子命令 `scan --input '<json>' --json` | ✅ |
| S4 worker 4 件套 | ✅ PASS |

---

## Phase-2 hooks

### Hook A · Mitre ATLAS 攻击模板库(派活 018-LAB-ATLAS)

**目标**:覆盖 Mitre ATLAS(Adversarial Threat Landscape for AI Systems)主流战术:
- AML.T0051 LLM Prompt Injection
- AML.T0054 Injection via legitimate resources
- AML.T0024 Exploiting model disclosure
- AML.T0050 Update pre-trained model
- ... 等 ≥ 10 个

**派活文档**:`018-LAB-ATLAS.md`(待起草)

```python
# src/ai_agent_lab/atlas_tactics.py
TACTICS = {
    "AML.T0051": {
        "name": "LLM Prompt Injection",
        "payloads": [
            "Ignore previous instructions and ...",
            "You are now ..."  ...
        ]
    },
    ...
}
```

- CLI payload 增量:`{"attack": "AML.T0051", "agent": "...", "iterations": 5}`
- 每次跑 → 不同 payload 变体

**为什么 Phase-2**:
- 现在只有 1-2 种攻击
- 真实红队测试要 ATLAS 全谱

### Hook B · 真实 LLM-as-judge 接入(替代 stub_router)

**目标**:目标 agent 用真 LLM(Qwen / GPT / Claude API),不再是 stub。

**派活文档**:`019-LAB-LLM-JUDGE.md`(待起草)

- 用 v0.1 `LLMRouter`(已存在)+ 真实 API key
- 不要在 `ai_agent_lab/__init__.py` 默认开真 API,必须显式环境变量 `LAB_LLM_KEY`
- 测试用 mock

**为什么 Phase-2**:
- stub router 是为 v0.5 demo(不被外部依赖)
- 真用必须真 LLM

### Hook C · 红队报告导出(JSON + Markdown)

**目标**:每次 scan 导出 1 份 markdown 报告:
- 跑过哪些 attack tactic
- 哪些失败(target agent 被攻破)
- 严重度分类

**派活文档**:`020-LAB-REPORT.md`(待起草)

- CLI 加 `report --format=md` 子命令
- 报告路径在 `output/`

**为什么 Phase-2**:
- 现在只有 envelope,没人类可读输出
- 安全工程师要 markdown 给客户/主管

---

## v1.0 路线图

```
v0.5 已冻结:基础攻击 + stub judge
v0.6: Hook A (ATLAS 模板库)
v0.7: Hook B (真 LLM judge) + Hook C (markdown report)
v1.0: 多模型对比(同一攻击对 GPT/Claude/Qwen 各自表现)+ CI 跑 nightly
```

---

## 不要做的事

- ❌ 不要在 test 中打真 LLM API(必须 mock,否则 CI 跑爆)
- ❌ 不要让 `ai_agent_lab` 把目标 agent 的对话历史写本地(隐私)
- ❌ 不要在 payload 加真实"恶意"内容(避免被 GitHub Action 拦)

---

**最近修订**: 2026-10-01 · Hook A/B/C 首版实现(见文首进展更新);2026-07-25 · Claude 起草 Phase-2 计划
**下次回看触发**: v0.6 启动 / Hook A 启动
