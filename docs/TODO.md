# 003 AI-Agent-Security-Lab · v0.1 TODO

> **项目状态**: PoC ✅ (58/58 tests passing)
> **共享接口**: [v0.1-contract.md](../../000shared-llm-core/docs/v0.1-contract.md) (已冻结)
> **派活模板**: [CODEX_INSTRUCTIONS.md](../../CODEX_INSTRUCTIONS.md)

---

## P1 · 本项目 v0.1 任务清单

| ID | 任务 | 状态 | 启动日 | 完成日 | 备注 |
|----|------|------|-------|-------|------|
| SCEN-001 | 内置脆弱 Agent 扩到 5 个 (SQLi、邮件、文件 RAG、Web 浏览器、Code-Act) | done | 2026-07-24 | 2026-07-24 | 5 profiles + CLI |
| ATTACK-001 | 攻击场景扩到 10 类 (加间接注入、token 窃取、shell escape 等) | pending | | | |
| SAND-001 | 沙箱化 (Docker 隔离 + syscall 白名单) | pending | | | |
| METRIC-001 | ASR (Attack Success Rate) 评估报告 | pending | | | |

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
