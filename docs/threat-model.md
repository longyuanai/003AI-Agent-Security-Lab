# AI-Agent-Security-Lab 威胁模型

> 版本：1.0-draft  
> 日期：2026-08-01  
> 范围：Commercial Preview 目标架构  
> 方法：STRIDE + LINDDUN；安全测试只允许自有、授权、靶场和合成 fixture。

## 1. 目标与安全结论

本模型回答三个问题：谁可能攻击平台、哪些边界不能互相信任、什么条件会阻止发布。

首个 Commercial Preview 的核心安全结论：

1. 控制面不能信任客户 Target、Attack payload、工具参数、LLM 输出或 Sandbox 回传。
2. subprocess 只能用于本地合成测试，不是商用隔离边界。
3. 单租户企业部署先于多租户 SaaS；任意代码执行先于公网开放必须升级为强隔离执行器。
4. 平台默认不保存 raw prompt、tool raw output、model messages 或 Agent 对话历史。
5. Attack Success 必须由客观 StateEffect Oracle 判定，不能由 Detector 或 Judge 自证。

## 2. 范围

### 2.1 范围内

- CLI、CI client、Web UI 和 `/v1` API。
- 身份认证、授权、租户和项目边界。
- PostgreSQL/SQLite metadata、object store 和 audit events。
- Worker、job lease、Sandbox Broker 和 isolated runner。
- Target、Attack、Detector、Oracle、Judge 和报告 adapter。
- LLM provider、客户 Target endpoint、MCP server 和 artifact download。
- 构建、依赖、容器镜像与发布链路。

### 2.2 范围外但必须声明

- 客户身份提供商自身安全。
- 客户生产 Agent 内部实现。
- 云厂商底层 hypervisor 和托管数据库内部控制。
- 客户自行关闭平台安全默认值后产生的风险；关闭动作仍须审计和明确告警。

## 3. 资产与安全目标

| 资产 | 机密性 | 完整性 | 可用性 | 主要目标 |
|------|--------|--------|--------|----------|
| API key / OIDC token | 极高 | 高 | 中 | 不进入日志、evidence、任务 payload |
| Target/LLM 凭据 | 极高 | 高 | 中 | secret reference、最小权限、可轮换 |
| 租户项目 metadata | 高 | 高 | 高 | 严格 tenant scoping、加密、备份 |
| EvaluationRun / Finding | 中 | 极高 | 高 | 防篡改、可追踪、不可跨租户读取 |
| Evidence / Report | 高 | 极高 | 中 | 最小化、hash、授权下载、TTL |
| Suite/Rule/镜像版本 | 低 | 极高 | 高 | immutable、签名、可复现 |
| AuditEvent | 高 | 极高 | 高 | append-only、限制删除、授权导出 |
| Sandbox host | 高 | 极高 | 极高 | 不被任务反控，不暴露控制面 secret |
| 服务容量与预算 | 低 | 高 | 极高 | 配额、限流、超时、成本上限 |

## 4. 威胁主体

- **未认证外部攻击者**：扫描 API、盗用下载链接、利用依赖或错误配置。
- **恶意或被攻陷的租户用户**：越权读取其他租户、提交资源耗尽任务、绕过 egress。
- **低权限内部用户**：尝试提升到 admin/auditor，读取 secret 或报告。
- **恶意 Target/Agent**：输出提示注入、超大数据、路径、命令、URL 或伪造 evidence。
- **恶意 MCP/Tool/LLM endpoint**：SSRF、重定向、DNS rebinding、数据外带或协议异常。
- **供应链攻击者**：污染 Python 包、容器镜像、GitHub Action 或构建制品。
- **运维误操作**：错误开放公网、保留数据过久、恢复失败、密钥进入日志。

## 5. 数据流与信任边界

```text
[User / CI]
     |  TB-1 Internet / enterprise network
     v
[API + AuthZ] ---- TB-2 ---- [Metadata DB / Object Store]
     |
     | signed, schema-limited job
     |  TB-3 Control plane -> execution plane
     v
[Sandbox Broker] ---- TB-4 ---- [Isolated Runner]
                                      |
                       TB-5 ----------+---------- TB-6
                       v                         v
                 [Target/MCP]              [LLM Provider]
                                      |
                                      v
                           normalized events only
                                      |
                                      v
                         [Oracle/Detector/Report]
```

### TB-1 · Client → API

不信任请求体、header、文件名、cursor、idempotency key 和用户提供 URL。要求认证、schema/size 限制、速率限制、统一错误、request ID 和审计。

### TB-2 · Application → Storage

不信任外部 ID 和 object key。所有查询必须 tenant-scoped；object key 由服务端生成；报告下载每次授权；数据库使用参数化查询。

### TB-3 · Control Plane → Execution Plane

任务必须最小化、签名、带过期时间和不可变 suite/image digest。Runner 不获得数据库、OIDC、GitHub 或控制面云凭据。

### TB-4 · Broker → Runner

Runner 是一次性、受资源限制、默认断网的敌对区域。返回数据必须验证 schema、类型、条数和总大小。

### TB-5 · Runner → Target/MCP

Target 和 MCP 输出是不可信内容；不能把工具返回当系统指令；URL、路径和工具参数在执行前经过 policy guard。

### TB-6 · Runner → LLM Provider

只允许管理员批准的 HTTPS endpoint；解析前后验证地址；限制 redirect；secret 由运行时注入且不得回传。

## 6. STRIDE 威胁登记

严重度：Critical 会导致跨租户、宿主机或 secret 全面失陷；High 会导致单租户敏感数据、执行边界或关键完整性失陷。

| ID | 类别 | 威胁 | 严重度 | 必需控制 | 验证 |
|----|------|------|--------|----------|------|
| TM-S-01 | Spoofing | 盗用 API key 创建运行 | High | hash 存储、scope、过期、轮换、限流 | 撤销/过期/错误 scope 测试 |
| TM-S-02 | Spoofing | 伪造 Runner 回传 | Critical | 双向认证、签名 job/result、nonce/expiry | 重放与错误签名测试 |
| TM-S-03 | Spoofing | 恶意 endpoint 冒充 LLM/Target | High | allowlist、TLS 验证、配置审计 | 错误证书/域名测试 |
| TM-T-01 | Tampering | 修改 suite/rule 后复用旧结果 | High | manifest hash、immutable version | hash 不一致拒绝测试 |
| TM-T-02 | Tampering | 修改 Report/Finding | High | artifact sha256、append-only audit | 下载校验与篡改测试 |
| TM-T-03 | Tampering | 非法运行状态回退或重复完成 | High | 状态机、乐观锁、幂等 | 并发状态转移测试 |
| TM-T-04 | Tampering | Target 伪造 objective success | High | Oracle 只接受受控 StateEffect | 伪造文本不得成功测试 |
| TM-R-01 | Repudiation | 用户否认启动攻击任务 | Medium | actor、request_id、policy、timestamp 审计 | audit 完整性测试 |
| TM-R-02 | Repudiation | 管理员修改 egress/retention 无记录 | High | 配置变更 append-only audit | 变更审计测试 |
| TM-I-01 | Disclosure | 跨租户 IDOR 读取 run/report | Critical | tenant-scoped repository、下载授权 | 全资源跨租户矩阵测试 |
| TM-I-02 | Disclosure | raw prompt/secret 进入日志或 evidence | Critical | allowlist schema、redaction、泄漏扫描 | canary secret 测试 |
| TM-I-03 | Disclosure | 错误响应泄漏堆栈/路径/SQL | Medium | 统一错误映射、服务端日志脱敏 | 异常路径测试 |
| TM-I-04 | Disclosure | SSRF 访问 metadata/control plane | Critical | deny egress、地址分类、redirect/DNS 校验 | link-local/private/rebind 测试 |
| TM-I-05 | Disclosure | 签名 URL 被长期复用 | High | 短 TTL、tenant binding、审计 | 过期和跨主体测试 |
| TM-D-01 | DoS | 超大 prompt/tool output/evidence | High | 请求/结果/字段大小上限 | 边界和超限测试 |
| TM-D-02 | DoS | fork bomb、死循环、内存/磁盘耗尽 | Critical | PID/CPU/RAM/disk/time limit、kill tree | 资源耗尽 fixture 测试 |
| TM-D-03 | DoS | LLM 成本耗尽 | High | token、cost、并发、每日预算 | 配额竞争测试 |
| TM-D-04 | DoS | 重复 idempotency 请求放大任务 | Medium | tenant + key 唯一、结果复用 | 并发重复请求测试 |
| TM-E-01 | Elevation | viewer 调用 run/cancel/admin | High | 服务端 RBAC | 权限矩阵测试 |
| TM-E-02 | Elevation | 容器逃逸控制宿主机 | Critical | strong sandbox、no socket/mount/secret | 独立渗透与逃逸测试 |
| TM-E-03 | Elevation | 路径穿越覆盖 artifact/配置 | High | server-generated key、safe join、只读 root | traversal/symlink 测试 |
| TM-E-04 | Elevation | 插件 import 执行任意初始化代码 | High | metadata discovery、签名/allowlist、隔离加载 | 未批准 entry point 测试 |
| TM-E-05 | Elevation | Worker 使用控制面过宽云权限 | Critical | 独立 service account、最小 IAM | 权限策略检查 |

## 7. LINDDUN 隐私登记

| ID | 类别 | 风险 | 控制 | 验证 |
|----|------|------|------|------|
| PM-L-01 | Linkability | 跨运行 hash 可关联客户输入 | tenant-scoped salt 或明确 hash 策略 | 相同输入跨租户不可关联测试 |
| PM-I-01 | Identifiability | 项目名、Target URL 暴露身份 | Confidential 分类、加密、最小导出 | 报告字段 allowlist 测试 |
| PM-N-01 | Non-repudiation | 过度审计损害隐私 | 审计目的限制、hash principal、受控导出 | retention/role 测试 |
| PM-D-01 | Detectability | 外部可探测客户正在评测 | 统一未授权响应、速率限制 | 枚举测试 |
| PM-D-02 | Disclosure | 模型消息或客户文件进入报告 | 默认不采集、schema allowlist | canary content 扫描 |
| PM-U-01 | Unawareness | 客户不知道数据流向 LLM | 运行前 provider/region/retention 展示 | policy acknowledgement 测试 |
| PM-NC-01 | Non-compliance | 超期保留或删除不完整 | TTL、tombstone、备份清除周期 | 删除验证演练 |

## 8. 关键滥用场景

### 8.1 间接注入诱导数据外带

1. Target 从文档或网页读取合成注入内容。
2. 内容要求调用网络或邮件工具传输数据。
3. Runner 将工具参数视为不可信；Policy Guard 拒绝未授权目的地。
4. Oracle 记录“尝试”与“实际效果”分离；被阻断不能计为攻击成功。
5. Evidence 只记录归一化 boundary 和 target 类别，不记录文档正文。

### 8.2 SSRF 到云 metadata

1. 用户、Target 或 LLM 产生 URL。
2. URL parser 规范化 scheme/host/port；只允许 HTTPS（fixture 除外）。
3. DNS 解析后检查所有地址；拒绝 loopback、link-local、private、reserved。
4. 每次 redirect 重新验证；连接地址必须与已验证地址一致。
5. 执行器 egress policy 作为独立第二层阻断。

### 8.3 跨租户报告下载

1. Tenant A 用户枚举 Tenant B 的 run/report ID。
2. API 从 authenticated tenant context 构造查询，不接受客户端 tenant ID。
3. Repository 以 `(tenant_id, resource_id)` 查询；不存在和无权限对外行为一致。
4. Object store key 不暴露给客户端；下载前再次授权。
5. 拒绝事件写入 audit，但不泄露资源是否存在。

### 8.4 沙箱任务接管宿主机

1. 恶意任务尝试访问宿主路径、进程、socket 或公网。
2. 容器无 root、无 capability、无宿主 mount、只读 root、独立临时卷。
3. seccomp/LSM/runtime 阻断危险 syscall；资源限制阻断耗尽。
4. 任务超时或取消时销毁整个隔离单元，而非只杀父进程。
5. Runner 身份没有控制面和其他租户权限；即使突破应用层也限制 blast radius。

## 9. 安全控制责任矩阵

| 控制 | Domain/Application | API | Storage | Runner | Ops/CI |
|------|--------------------|-----|---------|--------|--------|
| Tenant scoping | Owner | Enforce context | Enforce query | N/A | Test |
| RBAC | Owner | Authenticate | N/A | N/A | Review |
| Evidence allowlist | Owner | Size limit | Encrypt/TTL | Normalize | Leak scan |
| SSRF/egress | Policy | Validate config | N/A | Enforce | Network test |
| Resource limits | Define policy | Accept budget | Track quota | Enforce | Capacity test |
| Secret handling | Reference only | Redact | Secret manager | Ephemeral inject | Secret scan |
| Artifact integrity | Hash manifest | Authorize | Store checksum | Produce hash | Verify release |
| Audit | Emit events | Actor/request ID | Append-only | Security events | Retention/alert |

## 10. 发布前安全测试清单

- [ ] 每个 API resource 的 viewer/operator/admin/auditor 权限矩阵。
- [ ] 每个 ID、cursor、artifact key 的跨租户访问测试。
- [ ] prompt、header、exception、tool output 中植入 canary secret，确认日志/evidence/report 均不存在。
- [ ] loopback、private、link-local、IPv6、decimal/octal IP、redirect、DNS rebinding SSRF 用例。
- [ ] path traversal、absolute path、UNC、symlink/junction 和 archive extraction 用例。
- [ ] CPU、memory、PID、disk、timeout、stdout/stderr 和 result size 上限。
- [ ] Worker 崩溃、lease 过期、重复回传、取消竞争和数据库部分失败。
- [ ] 依赖、容器、IaC、secret、SAST、SBOM 和制品签名检查。
- [ ] 备份恢复、密钥轮换、API key 撤销、用户移除和数据删除演练。

## 11. 残余风险与接受条件

| 风险 | Preview 处理 | GA 要求 |
|------|--------------|---------|
| LLM provider 保留输入 | 默认 offline；显示 provider policy | 企业可选 zero-retention endpoint，合同说明 |
| Docker kernel 共享 | 单租户、合成/受控任务 | 不受信任代码使用 gVisor/Kata/microVM |
| Detector/Judge 误判 | Oracle 独立、报告显示三种信号 | 扩大 corpus、置信区间、人工复核流程 |
| 插件供应链 | 内置/allowlist 插件 | 签名、来源验证、隔离 certification |
| Hash 关联性 | 不把 hash 当匿名化 | tenant-scoped 策略与隐私评审 |

Critical 或 High 残余风险必须有负责人、截止日期、补偿控制和书面风险接受；否则阻止发布。

## 12. 评审与更新触发

以下任一事件发生时必须更新本模型：

- 新增外部数据流、生产依赖、LLM provider、Target adapter 或插件加载方式。
- 开启多租户、任意代码、公网 egress、raw evidence 或 SaaS。
- 调整身份、租户、存储、Runner 或密钥边界。
- 出现安全事件、Critical/High 漏洞或独立渗透测试发现。
- 每个 Commercial Preview/GA 发布候选，以及至少每季度一次。

评审参与：产品负责人、应用开发、安全、运维；GA 增加隐私/法务与独立测试方。

