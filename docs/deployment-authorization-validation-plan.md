# 部署权限验证计划与本地验收材料

日期：2026-09-28。**本轮只准备计划与材料；真实部署验收未执行、未通过。** 不创建外部资源，不连接生产或测试 PostgreSQL，不配置真实 IdP，不接收真实凭据，不启动部署。A1 与 A2 实现均不在本轮范围。

## 1. 依据、版本和支持边界

根仓 HEAD `4235350fbd4d8858fbaac23f380e6cce87688d61`，开工干净；Agent HEAD `74fbe58da54e5999acefaed3c572c46c831fe86e`，存在既有未提交权限代码、文档、A0 测试和证据。本轮不修改产品源码与 A0 报告/测试。开工清单、TODO 备份路径及本轮结果位于 [evidence/deployment-plan-20260928](evidence/deployment-plan-20260928/)。开工时 A0 的 `verified-integrity.json` 所列源码、测试、交付文件摘要全部匹配；本轮仅在 TODO 原有内容上更新后续任务。仅复核文件与记录，**没有重跑 A0 全套测试，A0 历史数字不计入本轮结果**。

| 代码/配置证据 | 能确认的形态 | 不能据此宣称 |
|---|---|---|
| `api/server.py:create_server_app` | 单主机 ASGI factory；disabled、local、api_key、oidc、api_key+oidc 五模式；SQLite 自动 schema/默认租户 | 已有集群编排或生产安全默认监听；local 不校验监听地址 |
| `storage/database.py`、pyproject psycopg | PostgreSQL SQLAlchemy 驱动路径；pool_pre_ping；服务不为 PostgreSQL 自动建表/租户 | 已验证数据库版本、TLS、连接池、行锁或生产迁移 |
| `migrations/env.py`、0001～0004 | Alembic 读取 LAB_DATABASE_URL；当前最新 revision 为 `0004_api_keys` | 已在线应用迁移；无环境变量时 ini 会退回 SQLite，必须禁止这种误用 |
| `auth.py:OIDCAuthenticator`、server | 固定非对称算法集合；校验签名/iss/aud/sub/iat/exp、租户与角色；本地公钥文件在启动时读入 | JWKS discovery/自动刷新、kid 多密钥选择、热重载或实时 IdP 用户禁用同步 |
| `application/service.py:process_next`、`storage/run_repository.py` | 可信调用者传 TenantContext；租户过滤、skip_locked 查询、owner/fencing/lease；服务认领租约 300 秒 | 已有常驻 worker/队列消费者、全局租户调度、长任务 heartbeat 集成；当前没有 worker CLI |
| FileArtifactStore | 本地文件根、受限 key、摘要校验、metadata 租户过滤 | 多主机共享存储一致性或 ACL 已验证；多实例必须能读取相同的已提交制品 |
| `api/app.py:_observe_response`、SafeJSONFormatter | request_id、路由模板、状态、耗时和结果；白名单 JSON，不记录头/正文 | HTTP 事件已关联 subject/tenant；formatter 支持 tenant_id_hash，但路由没有提供它；没有 append-only 审计服务 |
| `operations/backup.py` | SQLite 一致性备份、校验 SHA-256/integrity、仅恢复到新路径 | PostgreSQL 备份/PITR 已实现或已经演练 |

本仓未发现 Dockerfile、Compose/Kubernetes 或独立 worker 部署配置。多 API 进程可按 ASGI 工具组织，但实际部署拓扑、进程管理、worker 启动器与共享文件布局必须先决策，不能凭现有类存在宣布多实例可交付。

## 2. 待决策参数与真实环境必要条件

配置模板 [validation/deployment-authorization.example.json](validation/deployment-authorization.example.json) 将以下决策全部留空；[env 参考模板](validation/deployment-authorization.env.example) 不可直接加载，未放任何凭据。

| 待决策项 | 必须形成的证据/约束 |
|---|---|
| 授权与隔离 | 测试负责人、批准范围、专用非生产环境标识、网络出口和可清理资源清单；禁止复制客户数据 |
| OS/运行时/版本 | 实际 OS、Python、依赖锁定方式、Agent 与 shared 源码提交及 dirty 摘要；各实例相同 |
| API 拓扑 | 至少两个可独立定位的实例、网关/TLS、受信 request ID 策略、时钟同步、实例日志标签及回滚流程 |
| OIDC | 真实测试 IdP/issuer、audience、受信 token 类型、算法、sub/tenant/roles 映射；仅测试账号，无生产 realm |
| 密钥轮换 | 当前单静态公钥模式下的协调停机或滚动重启顺序、失效窗口与回滚；要求无缝双钥重叠时先单列产品任务 |
| 身份生命周期 SLA | 已签发 token 在角色降级/账号禁用后允许存活多久；当前按 token claims，未过期旧 token 不因新 token 签发自动失效 |
| PostgreSQL | 实际版本、专用数据库、数据库/迁移/应用权限分离、TLS、连接/事务策略、备份位置与恢复验证；不填真实 DSN |
| 初始化与迁移 | 专人执行 Alembic、校验 head；单独受控创建两个测试租户。PostgreSQL 下 LAB_TENANT_ID 不会自动创建它们 |
| worker | 启动器与 supervisor 尚未提供；实例 owner、可服务租户白名单、认领/重试/超时、运行状态观测、测试同步屏障 |
| 制品 | 所有参与实例可访问相同逻辑存储，约定路径、专用 campaign 子树与 OS ACL；记录 DB metadata→文件映射 |
| secret 注入 | 审批后的 secret 引用和运行时注入机制；只记录引用编号，不收集 key/token/密码/私钥；api_key 模式 pepper 至少 32 bytes |
| 日志 | 聚合、保留期、访问控制、时间同步、脱敏检查、可信身份关联与不可篡改要求；现有 actor 关联缺口需单独处理 |
| 备份/恢复/清理 | 测试 DB 与制品的同一恢复点、RPO/RTO、恢复演练目标、清理 owner、账号/key/数据回收时点 |
| A2 边界 | 只跑既有合成 fixture，不接受不可信代码；生产执行隔离另行验收 |

这些描述填齐只能表示“元数据可评审”，不是环境存在或已验收。脚本 `check` 即使描述全填仍退出 4：没有真实执行证据。

## 3. 验收层级和统一证据

- **L0 / A0 已覆盖**：已有代码及此前本机负例，引用 A0 报告/具体测试名；本轮不重复计数。
- **L1 / 可补本地验证**：离线配置材料检查、合成签名 token、SQLite/ASGI 的限定行为；本轮新增用例仅说明本机机制。
- **D / 必须部署执行**：真实测试 IdP、至少两实例与实际 PostgreSQL/制品/日志链。缺任何前置条件记 `blocked` 或 `not_run`，不能 `pass`。

每条证据使用 `campaign + case_id + attempt`，记录：UTC 时间、执行者、应用/规则/依赖版本与 dirty 摘要、环境清单引用、各 API/worker 实例 ID、请求 ID、合成账号别名/资源 ID、操作参数类别、预期、实际状态与错误码、前后行数/摘要、脱敏证据引用、清理回执及结果。允许结果为 `not_run/blocked/pass/fail`；pass 必须有该层的执行证据。不要保存 Authorization、JWT、密码、私钥、真实正文、连接字符串或含密钥的命令。JWT 只记录测试类别/有效时间/公钥指纹，不存 token 本身。实例/账号别名和证据访问权限需受控。

L0 的具体索引如下，均只引用 [A0 报告](a0-authorization-baseline-20260927.md) 及其 JUnit，未在本轮重跑；每行仅证明已列出的子项，不代表整条部署用例通过。

| 范围 | 现有测试定位 | 尚需补充的部署证据 |
|---|---|---|
| OIDC | `tests/test_auth.py::test_oidc_rejects_invalid_identity_claims`、`test_oidc_rejects_wrong_signature_and_non_asymmetric_configuration` | 历史仅错误 issuer/audience、过期、未知角色、空 tenant、错误签名及 HS256 配置拒绝；缺失 claims、未来 iat、轮换、真实 IdP 映射仍需验证 |
| 跨租户/生命周期 | `tests/test_tenant_isolation.py::test_cross_tenant_completed_reports_are_not_downloadable`、`test_cross_tenant_cancel_is_same_as_random_missing_id`；`tests/test_a0_authorization.py::test_verified_identity_still_requires_an_active_tenant` | 实际 PG/TLS/网关与停用竞态 |
| 身份/RBAC | `tests/test_a0_authorization.py::test_every_resource_rejects_invalid_authentication`、`test_http_role_denial_for_every_forbidden_operation`、`test_service_role_denial_happens_before_delegation` | 多实例角色/撤销传播和 IdP 生命周期 |
| worker | `tests/test_a0_authorization.py::test_worker_suspension_discards_reports_and_keeps_other_tenant_untouched`、`test_worker_claim_cannot_heartbeat_or_transition_through_other_tenant`；`tests/test_run_repository.py::test_stale_worker_cannot_heartbeat_or_transition_after_reclaim` | 多进程锁、实际租约时序、调度者授权 |
| 重启/日志 | `tests/test_commercial_e2e.py::test_service_restart_reads_persisted_run_and_artifacts`；`tests/test_a0_authorization.py::test_denied_request_does_not_log_bearer_secret` | 独立进程重启、共享存储、完整日志链与 actor 关联 |

## 4. 验收矩阵

下表的“部署预期”是需要满足的验收要求；“当前限制”不能冒充通过。通用前置 P：第 2 节决策经确认、仅专用测试环境、备份恢复点已验证、用生成清单里的 A/B 合成租户与角色。没有 P，不发出真实请求。

清理代号：C1=撤销测试 token/session/key、禁用并移除本 campaign 测试账号；C2=按 exact-ID 清单清理本 campaign 数据/制品；C3=停止测试 worker、恢复原测试配置/密钥、确认队列无遗留；C4=保留脱敏证据与恢复回执，按已定期限删除。详细顺序见 §6。

| ID | 层级/已有证据 | 前置条件 | 操作 | 预期结果/当前限制 | 必需证据 | 清理 |
|---|---|---|---|---|---|---|
| OIDC-01 | L0 签名/算法负例；D 必跑 | P；真实测试 IdP、受信公钥、合法合成账号 | 合法 token 对照；错误签名、篡改 payload、none/不允许算法分别访问两实例 | 对照有权操作 2xx；无效签名/算法 401，不回显 token；禁用模式不能误作认证通过 | 每类每实例状态、错误码、key 指纹、request ID | C1/C3/C4 |
| OIDC-02 | L0 iss/aud 负例；D 必跑 | P；批准 issuer/audience | 由测试 IdP 发错误 issuer/audience 的测试令牌或经受控离线构造，再调用两实例 | 不匹配 401；正确值通过；不能拿签名本已错误的 token 证明 iss/aud 校验 | 发行配置引用、签名已有效说明、分类结果 | C1/C4 |
| OIDC-03 | L0 expiry；L1 可补时间边界；D 时钟必跑 | P；可信时钟、令牌 TTL 已定 | 合法、已过期超过容忍期、未来 iat、缺 sub/iss/aud/iat/exp 分别测试 | 无效 401；当前 leeway 默认 30 秒且 server 无环境参数，不要求 exp 刚过立即拒绝；实测边界并批准 SLA | 节点时钟偏差、非秘密时间字段、请求时间与结果 | C1/C4 |
| OIDC-04 | L1 本轮静态公钥重载限制；D 必跑 | P；旧/新公钥发布和回滚计划 | 在测试 IdP 轮换，逐实例验证新旧 token；按批准顺序替换公钥并重启，再复测 | 仅改文件不会更新已启动实例；旧实例仍认旧钥、新钥拒绝；重启后反转。必须接受受控切换窗口；零停机双钥要求未实现时 blocked | 文件指纹、实例启动时间、四格新旧 token 结果、回滚回执 | C1/C3/C4 |
| OIDC-05 | L0 claims/tenant 检查；D 必跑 | P；真实 IdP 测试租户/角色映射已审 | 合法 A/B；缺失/空/未知角色、缺 tenant、未知/停用 tenant；伪造 header/query/body tenant | claims 无效 401；身份有效但租户不可用 403；外租户资源 404/取消409；映射以已签名 claims 为准。IdP 必须禁止用户自行修改受信 tenant/role 属性 | IdP 映射配置引用、账号别名、每实例响应和资源未变证明 | C1/C2/C4 |
| OIDC-06 | L1 本轮旧 token 角色保留；D 生命周期必跑 | P；降权/账号禁用/token 撤销 SLA 已定 | 测试账号 admin→viewer，分别用旧/新 token；再禁用账号，验证刷新和旧 token 使用 | 新 token 受新角色约束；当前旧 token 未过期仍保留原角色，无 introspection。若要求即时用户失效则 fail/blocked，先做独立修复；租户停用仍可拒绝业务 | 操作时间、旧新有效区间、每实例权限结果、批准的失效上限 | C1/C3/C4 |
| AUTH-01 | L0 跨租户项目/幂等；D 必跑 | P；A/B 管理员各创建项目 | A/B 列表、以 B 提交 A project_id 创建 run，双方用同一幂等键 | 各自列表；外项目404，A数据未变；同键不同租户产生各自 run，不串用 | 项目/run exact IDs、tenant predicate 对应结果、前后行数 | C1/C2/C4 |
| AUTH-02 | L0 run/取消/制品 IDOR；D 必跑 | P；A queued 和 completed run，B无权 | B 读/取消 A run、下载 json/markdown，与随机缺失ID对照；owner正例 | 读取/报告404；取消409，与缺失语义相同；A状态/文件摘要未变；制品不经绕过授权的直链暴露 | 状态/错误码、owner对照、metadata/文件摘要、网关直链检查 | C1/C2/C4 |
| AUTH-03 | L0 六操作凭据及角色矩阵；D 必跑 | P；A/B V/O/A/D 账号，签发测试API key仅在该模式启用时 | 各角色遍历六操作；缺失/失效凭据；API key 撤销跨实例复测 | V仅读；O读/建run/取消但不能建项目；A当前资源全部；D无客户报告权；401/403一致。撤销旧key后两实例均拒绝 | case×角色×实例矩阵、key公共ID、DB无越权变化 | C1/C2/C4 |
| AUTH-04 | L0 停用及worker阶段检查；D 竞态必跑 | P；可受控切换租户状态、任务同步屏障 | active→suspended 时并发读/写/下载；worker认领前、评估后、制品后停用；恢复后复测 | 新业务请求拒绝；worker阶段检查阻止提交并清理。当前检查点间有竞态且不立即中止执行；必须约定截止点并在真实事务时序证明，无证据不得通过 | 时间线、事务/租约/状态、文件清理回执；B对照不变 | C1/C2/C3/C4 |
| MULTI-01 | L0 单进程仓储租约；D 必跑 | P；实际 PostgreSQL、两个独立worker、tenant白名单 | 同步认领同一A队列；B worker尝试A任务；交换claim进行heartbeat/transition | 有效租约仅一个owner；B不能取得/推进A；写入/制品仍归原租户；SQL skip_locked 的实际行为需实测 | worker PID/实例、claim owner/token/tenant、任务状态、重复执行计数 | C2/C3/C4 |
| MULTI-02 | L0 同租户幂等及跨租户同键；D 并发必跑 | P；两API实例与共享PG | A同键同时创建run；A/B同键并发；多角色并发读取/写入 | 同租户不重复创建；返回同run或明确可解释冲突，不可泄漏/500掩盖；跨租户各自幂等。当前并发异常处理未现场验证 | 并发屏障、每请求返回、tenant+key唯一性查询、错误日志 | C1/C2/C3/C4 |
| MULTI-03 | L0 cancel/fencing；D 必跑 | P；两个worker、可控制暂停/租约过期 | API-1取消、API-2读取；暂停旧worker、超时后新worker重领，再恢复旧worker | 已取消不回到完成；陈旧token不能续租/提交；报告不留未授权残件；B任务不变；不得将取消数据库状态当作子进程已终止 | 前后fencing/owner、取消与提交时间线、artifact清单、worker日志 | C2/C3/C4 |
| MULTI-04 | L0 SQLite重启持久性；D 必跑 | P；版本一致的API/worker、共享制品根、回滚计划 | 重启一个API/worker，保留数据库；以撤销key/停用tenant/跨tenant请求复测；由另一实例读已完成报告 | 认证配置不回落local/disabled；授权拒绝保持；合法报告可读且摘要一致；服务重启不能凭旧内存权限绕过DB状态 | 启动配置指纹、health与受保护接口结果、报告摘要、重启日志 | C1/C2/C3/C4 |
| AUDIT-01 | L0 token不进日志；L1本轮JSON证据；D 全链必跑 | P；网关/API/worker/DB日志可控收集 | 用本campaign合成头/正文canary触发401/403/404/409/422/500；按request ID找事件 | 拒绝可定位到时间/路由/状态/实例；所有日志和错误中不含令牌/敏感正文；500仅由受控故障注入产生 | 经脱敏的全链日志片段、canary搜索计数、响应request ID | C1/C3/C4 |
| AUDIT-02 | L1本轮确认actor关联缺口；D要求待补 | P；审计追踪需求与身份散列策略批准 | 两不同账号发相同拒绝操作；尝试从现有HTTP日志关联主体/租户；检查客户端伪造request ID策略 | 当前仅request相关，缺actor/tenant字段，不能声称完整身份审计。需要可信事件关联且不泄密；要求完整主体归因时本项blocked | 本地复现测试、字段清单、独立修复任务编号；未来身份关联证据 | C1/C4 |
| AUDIT-03 | D，当前无完整实现证据 | P；聚合/访问/保留/不可篡改策略 | 非审计角色尝试访问日志；模拟实例重启/轮转、遗漏、时间漂移；核对拒绝事件完整性 | 日志访问最小化、关键事件可恢复/关联、保留与删除可验证；普通文件日志不等于append-only审计 | 日志ACL、轮转/丢失检测、保留策略和审计查询回执 | C3/C4 |
| RECOVERY-01 | SQLite helper仅代码依据；D PG必须演练 | 专用测试环境、已批准备份/恢复工具和独立恢复目标；作为P的恢复准入步骤 | 停止本campaign写入，备份专用PG与制品；恢复到另一个空测试目标；复测停用/撤销/跨tenant拒绝及owner报告 | 数据和artifact同一恢复点，摘要一致；授权状态不回退到更宽松权限；无证据不得开始破坏性/故障测试 | 备份校验、恢复日志、版本/行数、权限复测、RPO/RTO实测 | C2/C3/C4 |
| RECOVERY-02 | L1只生成dry-run；D实际清理待授权 | P；测试已停止，所有actual IDs与归属已复核 | dry-run精确清单→人工复核→撤销身份/租约→清理本轮行和artifact→复查 | 不匹配campaign/tenant或未知残件立即停止；不按前缀模糊删除；无生产/他租户数据受影响 | 清理前后exact-ID清单、计数、备份引用、双人/负责人审批记录 | C1/C2/C3/C4 |

## 5. 本地材料与执行顺序

沿用标准库、现有 pytest/PyJWT/cryptography/SQLite/FastAPI 测试工具，不增加生产依赖。

矩阵中的六操作为 `POST/GET /v1/projects`、`POST /v1/runs`、`GET /v1/runs/{run_id}`、`POST /v1/runs/{run_id}/cancel`、`GET /v1/runs/{run_id}/reports/{format_name}`（json/markdown各测）。V/O/A/D分别为viewer/operator/admin/auditor；auditor只有预留audit:read，当前没有审计HTTP路由。租户管理、key管理和worker调用属于可信管理边界，不能把直接构造TenantContext当作用户认证。

未来请求的合成正文：建项目使用 `{"name":"<清单内project_names项>","target_policy":{}}`；建run使用 `{"project_id":"<刚创建的本租户project_id>","suite_version":"built-in-v1","seed":0,"idempotency_key":"<清单内idempotency_key>"}`。跨租户负例仅替换批准的另一个测试租户ID；拒绝后同时核对目标行/制品未变。HTTP token由未来执行者的受控运行时注入，不写入命令行、脚本参数或证据。当前材料脚本不会发送这些请求。

1. `scripts/deployment_authorization_materials.py prepare` 生成纯本地 bundle：待决策配置、A/B各四角色的账号**别名**、项目名称、跨租户同幂等键、合成正文canary、19条全为 not_run 的证据模板。**不创建账号、租户、数据库、key或token**。
2. `check` 只检查决策元数据形状/缺项，不读真实环境变量、不连接任何服务、不输出配置值。缺决策返回4；全部填写仍返回4（not_verified）。不能拿字段填全当 readiness check。
3. `cleanup-plan` 固定 dry_run，只接受原样的合成清单，输出本campaign逻辑资源与人工清理前置条件；不访问数据库/文件制品，不删除、不提供 apply 选项。实际运行产生的 ID 必须另存受控 inventory，不能修改合成模板扩大范围。
4. 本地测试只验证脚本错误/保留证据语义，以及真实签名但**本地自造** token 的公钥重载、旧角色token行为和JSON日志缺口；不是 IdP/PG 验收。
5. 环境决策与修复任务处理后，另一次明确授权才部署隔离环境，顺序为：备份恢复准入→正例健康与身份→OIDC负例→跨租户/RBAC→多实例竞争/取消/重启→全链审计→清理与恢复复核。每阶段失败停止下一阶段，不靠停用认证/放宽权限取得绿色结果。

Agent 仓 PowerShell（目录名仅作本轮合成标识）：

```powershell
$pythonExe = '<python-3.14>\python.exe'
$env:PYTHONPATH = 'src;..\000shared-llm-core\src;.'
& $pythonExe scripts/deployment_authorization_materials.py prepare --campaign authval-20260928 --output-dir <新的本地目录>
& $pythonExe scripts/deployment_authorization_materials.py check --config <本地目录>/config.json
# 预期退出4：真实部署未验证；不要改成成功。
& $pythonExe scripts/deployment_authorization_materials.py cleanup-plan --bundle <本地目录>
```

prepare exit0仅代表材料生成；cleanup-plan exit0仅代表预览；参数/JSON/范围错误 exit2。已有输出目录拒绝覆盖。stdout JSON 可重定向到**新**证据文件。脚本没有 live、DSN、token 或部署参数，不接受实际凭据。

## 6. 隔离、备份恢复与清理方法

**测试隔离**：独立数据库/存储根/IdP测试空间；非生产网络和命名；禁止生产DSN、共享客户数据库schema、复用客户subject。每次用新的 `authval-` 加8～24位小写字母数字标识。账号别名不等于可信资源归属，实际创建后登记 account/tenant/project/run/artifact/key 的 exact IDs、创建者、时间、DB/文件归属和版本。不得将本轮清理应用到其他campaign。运行前确认停止机制与环境负责人在线。

**备份与恢复**：当前 SQLite helper 可用于独立本地练习，不能备份 PostgreSQL。未来PG测试须由DB负责人按实际版本选择受支持工具、准备受限备份存储和凭据运行时注入，备份数据库与制品的一致恢复点并记录摘要。先恢复到**新的隔离目标**并验证迁移版本、租户状态、revoked keys、metadata/file hash与权限负例，再开展故障/清理测试；不得覆盖运行中的数据库。迁移回滚优先从已验收备份恢复，不能假定 downgrade 无损。RPO/RTO、本轮测试数据保留期未定前不得破坏性操作。本轮不生成通用 drop/truncate/delete SQL。

**清理顺序**：停止流量/worker并确认无有效租约写入→保存受限脱敏证据与备份→撤销本campaign测试key/session，禁用测试账号→按inventory逐项确认租户归属与引用关系→经授权移除本轮artifact文件及metadata、runs、projects、keys、tenants，并删除/禁用本轮IdP账号→验证零遗留及其他租户摘要未变→保留清理回执。数据库外键可能级联，因此先审查每条依赖资源，禁止仅依赖级联“方便清空”。有未知残件、活动任务、归属不符、备份不可恢复则只预览并停止。真实清理工具要另行提供针对精确ID的事务和回滚，不得复用无租户作用域的全表脚本。

**日志/本地材料**：保留脱敏报告、版本、清理回执；按批准期限由文件所有者处理本地bundle，脚本不会删除任意目录。合成密钥测试只将公钥写入 pytest 独立临时目录，私钥/token 仅在内存；不写入报告或Git。

## 7. 准入、停止条件与独立待办

真实测试准入要求：P全部满足，源码/配置固定，恢复演练通过，无真实客户数据，所有外部目标在授权清单，测试预期和生命周期SLA明确。`check` 返回4并不阻止本轮材料完成，但表示**没有部署通过结论**。真实执行不能靠修改 evidence-template 的 status 手工伪装通过，必须附带可独立核对的D级证据和负责人结论。

立即停止：资源越出租户/授权边界、出现真实数据或凭据、测试指向生产、备份失败、跨实例配置不一致、无法关联关键证据、清理归属不明确、取消/停用后违反已批准截止点仍写入、任何安全负例意外允许。保留脱敏失败信息、冻结本campaign流量、按批准回滚；不重试到“看似通过”后隐藏初次失败。

| 独立任务 | 当前证据/性质 | 本轮处理 |
|---|---|---|
| DEP-AUTH-01 静态公钥轮换 | 新本地测试证明只改文件不更新旧实例；当前能力限制，非自动轮换承诺 | 指定公钥分发/协调重启/回滚；若业务要求热轮换/重叠，另开实现任务 |
| DEP-AUTH-02 角色与用户即时失效 | 新token降权不会撤销未过期旧token；当前按claims授权 | 先定token TTL/失效SLA；若要求即时失效，单列修复，不能假装已支持 |
| DEP-AUTH-03 拒绝事件主体关联 | 新本地日志测试证明403事件有request ID但无subject/tenant关联 | 对完整审计需求是可复现覆盖缺口；单列最小审计字段/可信关联修复及隐私测试，本轮不改路由/契约 |
| DEP-MULTI-01 worker部署入口 | 仅process_next内部调用，无常驻启动/租户调度工具 | 先定义受信worker生命周期和租户授权配置，后续独立实现/验收 |

上述测试的“通过”仅表示当前行为被准确记录，不表示缺口满足部署验收。

## 8. A2 独立执行隔离边界

A2 依赖已批准的OS/容器或其他隔离运行时、宿主权限与网络策略、可信worker调度、制品挂载及授权映射、资源/进程管理与故障回收。其独立验收至少覆盖：宿主凭据不可见、默认禁外网/元数据、非特权用户、只读根与受限写目录、跨租户文件拒绝、CPU/内存/磁盘/进程上限、超时/取消后的**完整进程树**回收、worker崩溃后残件回收与审计证据。每项必须在实际运行时执行授权合成负例。

本计划中的DB取消状态、Python socket守卫、Mock/SQLite或subprocess超时都不能证明上述隔离。A2 未通过前不开放任意不可信代码执行。本轮不选新技术栈、不实现生产沙箱、不部署任何容器。

## 9. 本轮材料验证

**计划与本地材料完成，真实部署验收未执行。** 本轮仅新测试文件最终运行 **12 passed、0 failed、0 skipped**；没有运行 A0 整轮，未访问真实 IdP、PostgreSQL、外部模型或部署环境。19项D级证据仍全部为not_run。证据位于 [本轮目录](evidence/deployment-plan-20260928/)，最终逐例结果见 [pytest-final.xml](evidence/deployment-plan-20260928/pytest-final.xml)。

| 实际检查 | 退出码 | 结论/记录 |
|---|---:|---|
| 新测试首次运行 | 0 | 12 passed，pytest.log；随后修正Lint代码再复跑 |
| 新测试最终运行 | 0 | 12 passed，pytest-final.log / final-checks.json |
| Ruff首次 / 最终 | 1 / 0 | 首次3处规则问题，仅改新文件，未压制规则；ruff.log / ruff-final.log |
| mypy旧工具 / 包路径配置 / 最终 | 1 / 2 / 0 | 旧TEMP工具缺少入口；恢复工具后遇namespace重复定位；加explicit-package-bases后strict检查2文件通过，各次日志均保留 |
| 固定mypy 1.20.2安装 | 0 | 仅新TEMP目录，使用缓存开发工具包；未改生产清单或全局环境 |
| prepare / check / cleanup-plan | 0 / 4 / 0 | 仅材料成功、真实验收未验证、dry-run删除0；material-commands.json |
| repair_links.py --check | 0 | 兼容链接目标均有效；未修复或递归复制链接 |
| git diff --check、材料空白检查 | 见final-integrity.json | 收尾检查覆盖已有tracked差异和本轮新增文本；不暂存文件 |

Python 3.14.6、pytest 9.1.1、Ruff 0.16.1、mypy 1.20.2；其余实际版本见 [runtime.json](evidence/deployment-plan-20260928/runtime.json)。旧TEMP工具在沙箱下还有目录读取权限报错，授权只读核查后确认入口文件确实缺失；这是环境问题。Git全局ignore读取权限警告未通过修改用户Git配置规避。链接检查首次控制台中文编码失真，UTF-8复查日志另存；链接状态本身没有失败。首次规范/工具配置失败均不算产品权限失败。

中断后继续核对时，本轮新TEMP工具入口和TODO临时备份也已不存在，原因未确定；已完成的测试和类型检查日志仍在仓内，本轮没有据此重复宣称执行。为保留文档回滚材料，已在内存中反向移除**仅本轮TODO改动**，与A0交付摘要逐字节匹配后保存 [TODO-before.md](evidence/deployment-plan-20260928/TODO-before.md)；核对记录见 [temporary-state.json](evidence/deployment-plan-20260928/temporary-state.json)。不要依赖TEMP长期保留。回滚只处理本轮新增文件与TODO差异，不对原dirty仓执行整体还原。

以下是本轮最终实际命令（Agent仓内执行；重新执行时请改用新的basetemp、输出目录与日志，保留现场证据）：

```powershell
$pythonExe = '<python-3.14>\python.exe'
$env:PYTHONPATH = 'src;..\000shared-llm-core\src;.'
$testTemp = '$env:TEMP\agent-deployment-plan-final-3e8e32be7e0d40a3a5bcb3ae79a90247'
& $pythonExe -m pytest tests/test_deployment_authorization_materials.py -q -o addopts= --basetemp $testTemp --junitxml docs/evidence/deployment-plan-20260928/pytest-final.xml
& $pythonExe -m ruff check scripts/deployment_authorization_materials.py tests/test_deployment_authorization_materials.py
& $pythonExe ../scripts/repair_links.py --check
$typeTools = (Get-Content docs/evidence/deployment-plan-20260928/mypy-tools.json | ConvertFrom-Json).target
$env:PYTHONPATH = "$typeTools;src;..\000shared-llm-core\src;."
$env:MYPYPATH = 'src;..\000shared-llm-core\src;.'
& $pythonExe -m mypy --strict --follow-imports silent --explicit-package-bases --cache-dir "$typeTools\cache" scripts/deployment_authorization_materials.py tests/test_deployment_authorization_materials.py
git diff --check
& $pythonExe scripts/deployment_authorization_materials.py prepare --campaign authval-20260928 --output-dir docs/evidence/deployment-plan-20260928/bundle
& $pythonExe scripts/deployment_authorization_materials.py check --config docs/evidence/deployment-plan-20260928/bundle/config.json
& $pythonExe scripts/deployment_authorization_materials.py cleanup-plan --bundle docs/evidence/deployment-plan-20260928/bundle
```

工具恢复实际使用 `& $pythonExe -m pip install --disable-pip-version-check --target $typeTools 'mypy==1.20.2'`，其中target是本轮新TEMP路径，详见mypy-tools.json。若该临时目录已清理，应重新建隔离工具目录，不从历史通过记录推断工具仍可用。

下一项最小任务：评审并填写16项非秘密环境决策，首先明确角色失效SLA、静态公钥切换窗口和审计主体归因要求；对已确认的DEP-AUTH-03另开最小修复任务。真实环境未获明确授权并满足准入条件前，只评审材料，不部署。
