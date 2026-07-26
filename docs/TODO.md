# 003 AI-Agent-Security-Lab · TODO

> **项目状态**: v0.6 · 252 passed / 4 skipped · ruff 全绿 · CI 已接入
> **共享接口**: [v0.1-contract.md](../../000shared-llm-core/docs/v0.1-contract.md) (已冻结)
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

### 待办(未做,需排期)

| ID | 任务 | 优先级 | 说明 |
|----|------|--------|------|
| SAND-002 | 真正的内核级沙箱 (Docker + seccomp) | P1 | 现为 Python 层 monkeypatch,`ctypes`/`os.write` 可绕过;文档已如实标注非安全边界 |
| DEF-001 | 防御者工具包 (输入过滤/工具白名单/Plan 验证器) | P1 | tech-spec §3 列为 Must,尚未开工 |
| SCEN-002 | 场景改为 YAML/DSL 加载 | P2 | 现在硬编码在 `attacks.py` |

---

## 派活模板（复制即可）

发给 Codex 时,把这个模板 + 上面 issue 表里挑的一行 ID 拼起来:

```
[{ISSUE_ID}] 003 AI-Agent-Security-Lab · {一句话}

## 背景
- 项目: 003 AI-Agent-Security-Lab
- 路径: E:\001项目\000开发\003AI+网络安全\003AI Agent安全靶场
- 接口契约: 000shared-llm-core/docs/v0.1-contract.md (已冻结)

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
