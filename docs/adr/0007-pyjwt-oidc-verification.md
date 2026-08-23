# ADR-0007：使用 PyJWT 验证 OIDC 签名令牌

- 状态：accepted
- 日期：2026-08-01
- 决策者：产品 / 开发 / 安全 / 运维
- 关联：AUTH-001、ADR-0005、TM-S-01、TM-E-01

## 上下文

ADR-0005 要求企业身份使用 OIDC，并校验 issuer、audience、signature、expiry 和允许算法。Python 标准库不提供 JWT、JWK、RSA/ECDSA 的完整安全实现；自行实现会形成不可接受的密码学与解析风险。

## 决策驱动因素

- 必须验证企业常用的非对称签名算法，且显式拒绝 `none` 和对称算法混用。
- 不访问未批准网络；首版从 secret/config volume 读取固定公钥。
- 依赖需支持 Python 3.11+，维护活跃且可锁定主版本。
- token、key 和 claims 原文不得进入日志或错误响应。

## 候选方案

### 方案 A：自行使用标准库实现 JWT

依赖少，但标准库缺少 RSA/ECDSA 验证，容易出现算法混淆、编码差异和 claim 校验缺口，不接受。

### 方案 B：PyJWT + crypto extra

API 小、可显式限定算法，并复用 `cryptography` 验证 RSA/ECDSA。增加一个直接依赖和其密码学依赖，需要持续补丁管理。

### 方案 C：完整 OAuth/OIDC 客户端框架

覆盖 discovery/login flow，但本服务只需 bearer token 验证，会引入不必要的会话和网络复杂度。

## 决策

采用方案 B，锁定 `PyJWT >=2.13,<3.0` 并启用 `crypto` extra。`OIDCAuthenticator` 只允许 RS/ES/EdDSA 非对称算法，必须提供固定 issuer、audience 和验证公钥，并要求 `sub/iss/aud/iat/exp`。首版禁止运行时自动拉取任意 JWKS URL；受控 JWKS 轮换在 NET-001 和运维密钥轮换设计完成后再引入。

## 安全与隐私影响

降低 TM-S-01/TM-E-01 的伪造和算法混淆风险。错误统一返回无细节认证失败；日志只记录 route/status/request ID。公钥不是 secret，私钥不得进入仓库或服务配置。

## 兼容与迁移

API key 与 OIDC 映射到同一 `Principal`，路由和 application service 不区分凭据类型。旧的健康端点保持匿名；商业资源路由在未配置认证时 fail closed。

## 验证

- RS256 正常、错误 signature、issuer、audience、expiry 和算法拒绝测试。
- API key one-time、digest、expiry、revocation 和篡改测试。
- viewer/operator/admin/auditor 路由权限矩阵和 secret canary 测试。

## 回滚

可把 `LAB_AUTH_MODE` 调整为 `api_key` 停用 OIDC。数据库迁移只新增 API key 表；回滚前先撤销所有相关凭据，再执行 0004 downgrade。生产环境不得回退到匿名或 local 模式。

## 后果

需要依赖漏洞监控和镜像更新。静态公钥轮换需要滚动配置更新；受控 JWKS cache、`kid` 轮换和 OIDC discovery 是后续运维增强，不影响 Principal 契约。
