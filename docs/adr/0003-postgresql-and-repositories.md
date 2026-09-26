# ADR-0003：PostgreSQL、Repository ports 与 Alembic 迁移

- 状态：accepted
- 日期：2026-08-01
- 关联：STORE-001、ART-001、TM-I-01、TM-T-03

## 上下文

商用服务需要租户隔离、事务、并发状态机、lease、备份和可审计迁移。开发者仍需要低门槛本地模式。

## 候选方案

1. JSON 文件：适合离线 artifact，不支持并发事务和可靠租户查询。
2. SQLite 全环境：本地简单，但生产并发写、运维和 lease 能力有限。
3. PostgreSQL 生产 + SQLite 本地：通过 repository port 保持 domain 独立。

## 决策

采用方案 3。生产 metadata 使用 PostgreSQL；本地单用户模式可用 SQLite。使用 SQLAlchemy 2.x 管理映射，Alembic 管理生产迁移。报告正文进入 object store，数据库只保存 metadata、object key 和 sha256。

Repository 方法必须从不可伪造的 `TenantContext` 获取 tenant_id。禁止通用 `get_by_id(id)` 暴露给 application layer；使用 `get(tenant_id, id)` 或 tenant-bound repository。

## 安全与隐私影响

对应 TM-I-01、TM-T-03、TM-E-03。参数化查询、最小数据库权限、TLS、加密存储、备份访问控制。数据库不保存 raw prompt/history；对象 key 由服务端生成。

## 兼容与迁移

迁移采用 expand → migrate → contract。应用至少兼容前一版 schema 一个发布窗口。SQLite 与 PostgreSQL 必须通过同一 repository contract suite，但 PostgreSQL 是生产行为的最终依据。

## 验证

- Repository contract、事务回滚、唯一约束和乐观锁测试。
- 所有实体跨租户读取/更新/删除测试。
- Alembic 从空库升级到 head、上一版本升级、备份恢复 smoke。

## 回滚

应用回滚只能回到仍兼容当前 schema 的版本。不可逆数据迁移必须先备份并提供恢复脚本；禁止自动 downgrade 丢数据。

## 后果

新增数据库与迁移运维责任，但获得可靠事务和可恢复状态。SQLite 只承诺开发便利，不承诺生产等价性能。

