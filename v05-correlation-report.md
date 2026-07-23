# AI Agent Security Lab · Cross-Scenario Correlation Report

_Generated at 2026-07-24T04:30:52_

## Summary

- Findings: **5**
- Correlated targets: **1**

## Findings

| Target | Scenario | Severity | Confidence | Title |
|--------|----------|----------|------------|-------|
| `lab-target-01` | `mcp-server-abuse` | critical | 98% | Unsigned MCP manifest combines poisoned metadata and secret access |
| `lab-target-01` | `web3-transaction-replay` | critical | 97% | Web3 transaction signature is replayable across executions |
| `lab-target-01` | `llm-prompt-injection-chain` | critical | 99% | Prompt injection chained into tool hijack and exfiltration |
| `lab-target-01` | `container-escape-host-intrusion` | critical | 99% | Privileged container path reaches the host boundary |
| `lab-target-01` | `npm-typosquat-supply-chain` | high | 95% | npm dependency is a one-character typosquat with install script |

## Correlated Targets

### `lab-target-01`

- Highest severity: **critical**
- Linked scenarios: **5**

## Correlation Graph

```text
lab-target-01 [critical]
├── mcp-server-abuse (0183a328-732d-4d29-932e-1a541dd6eac9)
├── web3-transaction-replay (38a44a9e-1877-453f-a10c-440010fec1b7)
├── llm-prompt-injection-chain (b41da336-3425-4d50-94ff-7e6fe9de9b94)
├── container-escape-host-intrusion (de6491aa-d8b4-4086-aede-6fa94ab1bfd7)
└── npm-typosquat-supply-chain (4ab8ee6f-0d19-4d88-a42a-a8e21e9586d4)
```
