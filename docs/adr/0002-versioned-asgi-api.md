# ADR-0002：FastAPI/Pydantic 版本化 ASGI API

- 状态：accepted
- 日期：2026-08-01
- 关联：API-001、TM-I-03、TM-D-01

## 上下文

商用版本需要版本化 HTTP API、严格 schema、OpenAPI、认证依赖和流式健康检查。现有 Click CLI 与 IntegrationGateway envelope 必须保留，HTTP 不能渗入 domain。

## 候选方案

1. Python 标准库 HTTP：依赖少，但 schema/OpenAPI/认证和异常处理需要大量自研。
2. Flask：成熟简单，但异步任务状态、类型化 schema 和 OpenAPI 需要额外组合。
3. FastAPI + Pydantic + Uvicorn：类型化 schema、OpenAPI 与 ASGI 生态完整，和当前 Python 类型模型匹配。

## 决策

采用方案 3。`ai_agent_lab.api` 只负责 HTTP schema、认证上下文、错误映射和 application service 调用。所有公开端点放在 `/v1`；实验接口不得混入 `/v1`。OpenAPI 是生成物，不是 domain source of truth。

FastAPI、Pydantic、Uvicorn 只在 API-001 issue 中一次性加入并锁定版本；实施前进行许可证和漏洞检查。既有 CLI 继续调用 application service，不通过本机 HTTP 绕行。

## 安全与隐私影响

请求、字段、文件和响应均有大小限制；错误使用稳定 code 和 request ID，不返回 stack、路径、SQL 或输入正文。文档端点在生产可配置关闭或受 operator 权限保护。

## 兼容与迁移

保留 `scan --json` 和 IntegrationGateway 契约。新 HTTP API additive 演进；删除或重命名字段必须进入新的 major version。

## 验证

- OpenAPI snapshot 和错误 envelope 契约测试。
- request ID、body size、validation、404/403 行为和 secret redaction 测试。
- `/health/live` 不探测依赖；`/health/ready` 准确反映依赖状态。

## 回滚

API 是可选入口；禁用 ASGI service 后 CLI/离线 benchmark 仍工作。不得用回滚删除已经持久化的新字段。

## 后果

增加三个生产依赖和 ASGI 运维面，换取稳定 schema 与减少自研安全代码。业务规则不得写在 route handler。

