# 003 AI-Agent-Security-Lab · TODO

> **项目状态**: v0.7-dev · 335 passed / 4 skipped · ruff 全绿 · CI 已接入
> **共享接口**: [v0.1-contract.md](../../000shared-llm-core/docs/v0.1-contract.md) + [v0.5-contract.md](../../000shared-llm-core/docs/v0.5-contract.md) (均已冻结)
> ⚠️ 共享内核实际版本是 **0.5.0**。`Finding` / `FindingSeverity` / `MultiAgentOrchestrator` /
> `RuleEngine` / `FindingRegistry` 定义在 **v0.5** 契约,v0.1 契约里没有 —— 只读 v0.1 会
> 以为它们不存在从而重新实现一遍。
> **派活模板**: [CODEX_INSTRUCTIONS.md](../../CODEX_INSTRUCTIONS.md)
>
> 跑测试前必须先 checkout 同级的 `000shared-llm-core`,见 README「Install」。
> 缺 `000shared-integration` 时,4 个 gateway 用例会 skip(不是失败)。

---

## P1 · 本项目 v0.1 任务清单

| ID | 任务 | 状态 | 启动日 | 完成日 | 备注 |
|----|------|------|-------|-------|------|
| SCEN-001 | 内置脆弱 Agent 扩到 5 个 (SQLi、邮件、文件 RAG、Web 浏览器、Code-Act) | done | 2026-07-24 | 2026-07-24 | 5 profiles + CLI |
| ATTACK-001 | 攻击场景扩到 10 类 (加间接注入、token 窃取、shell escape 等) | done | 2026-07-24 | 2026-07-24 | 10 detector-backed classes |
| SAND-001 | 沙箱化 (Docker 隔离 + syscall 白名单) | done | 2026-07-24 | 2026-07-24 | stdlib subprocess guard |
| METRIC-001 | ASR (Attack Success Rate) 评估报告 | done | 2026-07-24 | 2026-07-24 | Markdown + JSON, 50 combos |

---

## P0 · 工程健康度整改(2026-07-26,见 AUDIT/003-S2.md)

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

### v0.7 派活(2026-07-26 拟)

差距分析: [SPEC-GAP-ANALYSIS.md](SPEC-GAP-ANALYSIS.md) · 可直接复制的派活单: [dispatches/v07-tickets.md](dispatches/v07-tickets.md)

| ID | 任务 | 优先级 | 依赖 |
|----|------|--------|------|
| ~~SPEC-001~~ | 修正 tech-spec 过期/矛盾 | ✅ done 2026-07-26 | 已直接执行,不必派 Codex |
| ~~DEF-001~~ | Defender Toolkit 四件套 | ✅ done 2026-07-26 | Coverage 10/10 · Task Utility 52/54 · CLI `defend` · 40 测试。**推翻了「工具名白名单即可」的假设**,详见 tech-spec §5.4 |
| ATTACK-002 | 补 Memory Poison / Plan Hijack / Model DoS 三大攻击类 | P1 | **无阻塞,可立即派** |
| ~~METRIC-002~~ | Defense Coverage / Task Utility / 真 Detection Latency / Cost | ✅ done 2026-07-27 | 六维度全接入 `ASRReport`;顺带发现 §12 剧本第 4-5 步叙事与单步路由器实现不符,已登记给 `SCEN-E2E-001` |
| SCEN-E2E-001 | 让 §12 旗舰剧本描述与实现对齐(改路由支持两步,或改文档如实描述单步) | P1 | **无阻塞,可立即派**(需人类先选方案 A/B,见派活单) |
| REMEDIATION-001 | Scenario 加 remediation,报告输出修复建议 | P2 | 无 |
| OWASP-001 | Scenario 加 owasp_ids,让覆盖率可计算 | P2 | 无 |
| REPRO-001 | CI 加「同 seed 跑两次 diff 为空」 | P2 | 无 |
| CI-002 | CI 加 checkout 000shared-integration,4 个 skip 用例真跑起来 | P2 | 无 |

> ⚠️ 派活时**必须**把 SPEC-GAP-ANALYSIS §6 的三条护栏抄进约束段:
> 新攻击类必须配良性近似样本、用判别式不用裸关键词、不得为压 FPR 削弱强信号。

---

### 待办(未做,需排期)

| ID | 任务 | 优先级 | 说明 |
|----|------|--------|------|
| SAND-002 | 真正的内核级沙箱 (Docker + seccomp) | P1 | 声称范围内的口子已补(见 SAND-003)。剩余 `subprocess` 子进程 / `ctypes` 直调 C 是进程内 monkeypatch 原理上够不着的,已有测试钉住行为;真要挡住必须上 OS 级边界。**注**:当前威胁模型是自写的合成 payload,不是不受信任代码,所以优先级低于 DEF-001 |
| SCEN-002 | 场景改为 YAML/DSL 加载 | P2 | 现在硬编码在 `attacks.py`。注意 tech-spec §5.3 声称是 YAML DSL 而 §13 实施指令是硬编码 Python —— 方案自相矛盾,SPEC-001 会先裁定走哪条 |

---

## 派活模板（复制即可）

发给 Codex 时,把这个模板 + 上面 issue 表里挑的一行 ID 拼起来:

```
[{ISSUE_ID}] 003 AI-Agent-Security-Lab · {一句话}

## 背景
- 项目: 003 AI-Agent-Security-Lab
- 路径: E:\001项目\000开发\003AI+网络安全\003AI Agent安全靶场
- 接口契约: 000shared-llm-core/docs/v0.1-contract.md + v0.5-contract.md (均已冻结)
  共享内核实际版本 0.5.0;Finding / MultiAgentOrchestrator / RuleEngine 在 v0.5 契约里

## 必须做的事
1. <具体动作 1,含文件路径>
2. <具体动作 2>
3. <具体动作 3>

## 验收
- [ ] pytest 全绿
- [ ] 新增测试 ≥ N 个
- [ ] CLI smoke test 通过 (粘贴输出)
- [ ] 改动文件清单 (git diff --stat)

## 回报格式
**ID**: <ISSUE-ID>
**Files changed**: <列表>
**Tests**: X/X passed
**CLI smoke**: <输出片段>
**Deviations**: <如有,说明原因>
```

---

## 复盘节奏

- 每周一 09:00: 跑 `pytest` 全量,状态写到本表
- 每周五 17:00: review 完成的 issue,标 done
- 每月 1 号: 检查 shared-llm-core 是否有 breaking change
