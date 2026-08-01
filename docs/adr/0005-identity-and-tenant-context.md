# ADR-0005：API key/OIDC 身份与强制租户上下文

- 状态：accepted
- 日期：2026-08-01
- 关联：AUTH-001、TENANT-001、TM-S-01、TM-I-01、TM-E-01

## 上下文

CLI/CI 需要非交互认证，企业用户需要 SSO。平台不应自行保存密码。tenant_id 如果来自请求 body/query，会导致可伪造租户上下文。

## 候选方案

1. 自建用户名密码：增加凭据存储、重置、MFA 和合规责任，不接受。
2. 仅 API key：适合 CI，不满足企业人员生命周期和 SSO。
3. 高熵 API key + OIDC：机器和人员分别使用合适机制，统一映射 Principal。

## 决策

采用方案 3。API key 至少 256 bit 随机，只展示一次，数据库存 `key_id`、HMAC-SHA-256 digest（服务端 pepper 在 secret manager）、scope、expiry 和 revoked_at。人员登录由企业 OIDC provider 完成；服务只验证 token 并映射 subject/tenant/roles，不存密码。

`TenantContext` 只能由认证中间件构造，route/body/query 传入的 tenant_id 不参与授权。Application service 接受 `Principal + TenantContext`，repository 再强制 tenant scope，形成两层控制。

## 安全与隐私影响

对应 TM-S-01、TM-I-01、TM-E-01。OIDC 校验 issuer、audience、signature、expiry 和允许的算法；禁止接受 `none`。认证失败日志不记录 token/key。

## 验证

- API key 创建、scope、过期、撤销和轮换测试。
- OIDC issuer/audience/alg/expiry/签名拒绝测试。
- 全资源 RBAC 与跨租户矩阵测试。
- header/token canary 不进入日志、错误或 evidence。

## 回滚

OIDC 可按部署禁用，但生产 API 至少保留 API key 认证。认证模块故障必须 fail closed，不能回退为匿名访问。

## 后果

需要 secret manager pepper、OIDC 配置与时钟同步。API key 不适合人员长期使用，UI 不得把它当 session token。

