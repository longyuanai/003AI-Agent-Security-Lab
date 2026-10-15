# 003AI-Agent-Security-Lab · SECURITY

核实日期：2026-10-15。依据本地README、构建清单和实际入口；本文件不把文档计划当成运行时验收。

## 目标与范围

在自有/授权场景组织安全实验、执行控制和证据；modules 下能力仓保留独立历史。

GitHub：[longyuanai/003AI-Agent-Security-Lab](https://github.com/longyuanai/003AI-Agent-Security-Lab)。知识笔记：Vault内 `03_Projects/AI-Network-Security/003AI-Agent-Security-Lab - Git关联.md`。

## 本项目安全边界

验证撤销、超时、取消、进程退出与恢复时的证据一致性；并发工作先固定快照后验收。

- 仅处理自有、授权、靶场或CTF资产；未知上传内容按数据处理，不作为脚本执行。
- API Key、Token、主密码、私钥、个人资料、客户数据与运行数据库不进入Git、公开Issue或知识备份。
- 真实外部模型、支付、生产数据库、Telegram/飞书操作与硬件烧录需各自明确授权；默认使用本地夹具。

## 报告与修复

维护者账号：[longyuanai](https://github.com/longyuanai)。敏感问题先使用仓库已启用的私下报告渠道；未确认渠道时，不把敏感原件写入公开Issue。没有编造支持版本或联系邮箱。

记录授权范围、根因、影响、脱敏复现、修复与回归证据；修改前保存可恢复版本。文档完善不等于产品通过全面安全审计。

## 现行依据

- [README.md](README.md)
- [CAPABILITIES.md](CAPABILITIES.md)
- [docs/tech-spec.md](docs/tech-spec.md)
- [docs/TODO.md](docs/TODO.md)
