# Architecture Decision Records

ADR 用来记录影响多个模块、生产依赖、数据兼容或安全边界的技术决策。已接受 ADR 是实现约束，不是建议。

## 状态

- `proposed`：评审中，不授权实现。
- `accepted`：已批准，后续实现必须遵循。
- `deprecated`：仍可能存在，但不得用于新实现。
- `superseded`：由新的 ADR 替代。

## 索引

| ADR | 决策 | 状态 |
|-----|------|------|
| [0001](0001-modular-monolith-and-runner.md) | 模块化单体控制面 + 独立执行器 | accepted |
| [0002](0002-versioned-asgi-api.md) | FastAPI/Pydantic 版本化 API 边界 | accepted |
| [0003](0003-postgresql-and-repositories.md) | PostgreSQL + Repository ports + Alembic | accepted |
| [0004](0004-database-leased-jobs.md) | PostgreSQL lease 任务队列优先 | accepted |
| [0005](0005-identity-and-tenant-context.md) | API key/OIDC 身份与强制租户上下文 | accepted |
| [0006](0006-isolated-container-runner.md) | 独立 Linux 容器 Runner | accepted |

## 新 ADR 流程

1. 从 [template.md](template.md) 复制并分配连续编号。
2. 描述上下文、决策驱动因素、候选方案、安全影响、迁移和回滚。
3. 新生产依赖、服务拆分、存储变化、认证变化和信任边界变化必须先有 accepted ADR。
4. ADR 不原地改写历史结论；重大变化新增 ADR 并标记 superseded。

