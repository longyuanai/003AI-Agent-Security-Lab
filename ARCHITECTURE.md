# 003AI-Agent-Security-Lab · ARCHITECTURE

核实日期：2026-10-15。依据本地README、构建清单和实际入口；本文件不把文档计划当成运行时验收。

## 目标与范围

在自有/授权场景组织安全实验、执行控制和证据；modules 下能力仓保留独立历史。

GitHub：[longyuanai/003AI-Agent-Security-Lab](https://github.com/longyuanai/003AI-Agent-Security-Lab)。知识笔记：Vault内 `03_Projects/AI-Network-Security/003AI-Agent-Security-Lab - Git关联.md`。

## 组件与代码入口

| 实际路径 | 责任边界 |
| --- | --- |
| [src](src) | 主要实现 |
| [modules](modules) | 独立能力Git仓 |
| [migrations](migrations) | 数据版本 |
| [scripts](scripts) | 作者/运维工具 |
| [tests](tests) | 测试 |
| [docs](docs) | 工程规范与说明 |

## 数据与控制流

以下链路对应README/规范描述；实现覆盖以代码入口和适用验证为准。

```mermaid
flowchart LR
    N0["授权与任务"]
    N1["准入/执行控制"]
    N2["受限工作进程"]
    N3["证据存储"]
    N4["报告"]
    N0 --> N1
    N1 --> N2
    N2 --> N3
    N3 --> N4
```

## 构建与依赖依据

- [pyproject.toml](pyproject.toml)：`Python`。

## 验证边界

验证撤销、超时、取消、进程退出与恢复时的证据一致性；并发工作先固定快照后验收。

## 现行依据

- [README.md](README.md)
- [CAPABILITIES.md](CAPABILITIES.md)
- [docs/tech-spec.md](docs/tech-spec.md)
- [docs/TODO.md](docs/TODO.md)
