# 部署权限环境决策评审

> **2026-09-30 当前评审入口：§11～§18。** §1～§10保留9月29日既有评审/实施记录，不将其中旧的“当前实现”作为今日代码事实。历史文档记载的三项批准保留原文；本轮未取得新的负责人确认，新增或调整推荐一律**待确认**。真实环境存在性未知，19项部署验收均**未执行**。本轮只修改本文件与TODO及评审证据，不修改产品或验收脚本。

日期：2026-09-29。**本文是供项目负责人确认的决策评审材料；除下方“已批准”列出的三项外，其余数值与策略仍为“建议”。真实部署验收未执行、未通过。** 评审轮不部署、不创建外部资源、不连接 IdP/PostgreSQL、不修改产品源码、不推进 A1/A2。

**负责人决定（2026-09-29，会话内确认）**：§9 三个问题均选 A。已批准：D07 失效上限方案 A（access token TTL 10 分钟，上限约 10.5 分钟，不做即时撤销）、D06 公钥轮换方案 A（15 分钟维护窗口、全部实例重启）、D13 审计归因方案 A（HMAC 主体/租户哈希 + 服务端 request ID + run 记录明文提交者）。同日授权实施 G1+G4，结果见 §8.1。其余 13 项决策仍为建议。

依据：[部署权限验证计划](deployment-authorization-validation-plan.md)（下称“计划”）§2 与 §4、[配置模板](validation/deployment-authorization.example.json) 的 16 个 `decisions` 键、[A0 基线](a0-authorization-baseline-20260927.md)、ADR [0005](adr/0005-identity-and-tenant-context.md)/[0007](adr/0007-pyjwt-oidc-verification.md)，以及下列现有代码（Agent 仓未提交工作区，HEAD `74fbe58`）。本轮未重跑 A0 或材料测试；“当前实现”均来自读代码，标注“推断”的条目尚无现场复现。

状态用语：**建议** = 本文推荐、待确认；**缺口** = 当前代码不具备；**W** = 环境与决策就绪后即可执行；**B** = 被现有产品能力阻塞；**F** = 需先完成下文独立修复任务。

## 1. 与决策相关的已核实代码事实

| 事实 | 代码位置 |
|---|---|
| OIDC 公钥只在 `create_server_app` 调用时 `Path.read_bytes()` 读一次；只支持单个 PEM，无 `kid` 选择、JWKS、刷新或热重载 | `src/ai_agent_lab/api/server.py:82-98` |
| OIDC 授权完全取自已签名 claims（sub/tenant/roles），无 introspection、无用户或令牌撤销表；`leeway_seconds` 默认 30，server 不传参、无环境变量；不限制 `exp-iat` 的最大寿命 | `src/ai_agent_lab/auth.py:208-266` |
| API key 每个请求都查询数据库，`revoked_at`/`expires_at` 立即生效；角色在签发时固定；CLI `issue-api-key`（TTL 1～365 天，默认 90）与 `revoke-api-key` 已有 | `auth.py:172-205`、`cli.py:222-294` |
| 每个服务操作都在事务内调用 `_require_active_tenant`；worker 在认领、EVALUATING 前、提交制品元数据前各检查一次；评估本身在内存中执行、不中断 | `application/service.py:115-243` |
| worker 仅以 `TenantContext` 运行，不携带提交者身份；`evaluation_runs` 表**没有** created_by 列（项目和 API key 有）；租约 300 秒，`process_next` 不调用 heartbeat；仓内无 worker 启动入口 | `service.py:127`、`storage/models.py:91-125`、`run_repository.py` |
| 取消只改数据库状态并清空租约；旧 worker 之后的状态转换因 owner/fencing 条件失败，已写制品被删除 | `run_repository.py:128-187`、`service.py:206-219` |
| HTTP 日志字段白名单：event/request_id/method/route/status_code/duration_ms/result/run_id/tenant_id_hash；路由只填前七项。`tenant_hash()` 已有但未被调用；无 subject、实例 ID | `observability.py:15-60`、`api/app.py:393-424` |
| `X-Request-Id` 只要满足 `[A-Za-z0-9._-]{8,128}` 就原样采用客户端值 | `api/app.py:45,333-336` |
| PostgreSQL 下不自动建表或租户；`TenantRepository.set_status` 存在，但没有创建/停用租户的 CLI 或 API | `server.py:53-58`、`storage/repositories.py:37` |
| 并发同键建 run：先查后插入，唯一约束冲突时 `flush()` 抛出的 `IntegrityError` 不是 `ValueError`，推断会变成通用 500（未复现） | `run_repository.py:35-57`、`api/app.py:102-110,285` |

## 2. 16 项非秘密环境决策

“需改代码”只指为了满足该决策的验收是否必须先改产品；G 编号见 §6。

| # / 模板键 | 当前实现 | 可选方案 | 建议选择（未批准） | 理由 | 必要环境 | 需改代码 | 对应验收 |
|---|---|---|---|---|---|---|---|
| D01 `test_environment_owner_and_authorization` | 无记录；计划要求负责人与范围 | ①负责人本人兼任环境/清理 owner；②另设运维 owner | ①；书面列出可删除资源和停止人 | 自有测试环境，人少，单点签字最简单 | 专用非生产主机/网段及其负责人 | 否 | 全部（前置 P） |
| D02 `operating_system_and_runtime_versions` | 本机 Python 3.14.6；依赖声明于 pyproject；无锁定部署镜像 | ①测试主机按 pyproject 新建 venv 并记录 freeze；②容器镜像 | ①；所有实例共用同一 venv，并记录提交与 dirty 摘要 | 不引入容器设施；A2 之外不需要镜像 | 负责人指定的 OS 与 Python 版本 | 否 | 全部证据头；MULTI-04 |
| D03 `api_instances_proxy_tls_and_clock_sync` | 单主机 ASGI factory；uvicorn 是声明依赖；无网关配置；request ID 可由客户端指定；日志无实例 ID | ①同主机 2 个 uvicorn 进程、各自 TLS；②前置反向代理统一 TLS；③多主机 | ①，端口区分实例，每实例独立日志文件作为实例标签；时钟使用主机 OS 时间同步 | 满足“两实例”且不新增网关；同主机时钟天然一致 | 内网测试证书来源；主机时间同步 | 实例标签与可信 request ID 建议并入 G1 | OIDC-01～06、AUTH-*、MULTI-02/04、AUDIT-01 |
| D04 `oidc_provider_issuer_audience_token_type` | 固定 issuer/audience；要求 sub/iss/aud/iat/exp；不区分 ID/access token（只检查 aud） | ①负责人现有测试 IdP 的独立 realm；②新建自托管测试 IdP；③离线自签发器 | 若已有测试 IdP 选①，否则②；**③不能替代 D 级验收** | OIDC-06 需要真实的账号禁用；离线签发只能作为 L1 | 测试 IdP（**本文不假设其已存在**）、专用 audience | 否 | OIDC-01/02/03/05/06 |
| D05 `oidc_algorithm_claim_mapping_and_test_accounts` | 允许 RS/ES/EdDSA；默认 RS256；claims 默认 `tenant_id`/`roles`（数组） | ①RS256+默认 claim 名；②ES256；③自定义 claim 名 | ①；按生成清单的 A/B×V/O/A/D 八个合成账号；tenant/roles 为管理员托管属性 | 与默认值一致，零配置差异；IdP 必须禁止用户自改这些属性 | IdP 属性映射能力 | 否 | OIDC-01/05、AUTH-03 |
| D06 `oidc_public_key_distribution_rotation_rollback` | 单公钥文件，启动时读取；换钥必须重启；无双钥并存 | A 维护窗口切换+全部重启；B 先实现多钥并存再滚动；C JWKS 自动刷新 | **A**，见 §4 | 测试环境可接受短暂 401；B/C 需要产品改动 | 公钥分发路径、文件指纹记录、旧钥保留 | A 否；B 需 G2；C 超出范围 | OIDC-04 |
| D07 `role_change_and_token_revocation_sla` | OIDC 旧令牌到期前保留原角色；API key 撤销立即生效；租户停用在下一请求/下一检查点生效 | A 以短 TTL 为上限；B 即时失效（introspection/撤销表）；C 较长 TTL | **A**：access token TTL 10 分钟，上限 TTL+30 秒，见 §3 | 无需新增设施；B 要求新增依赖或数据表 | IdP 可配置 TTL 与账号禁用 | A 建议 G3；B 需要另立实现任务 | OIDC-03/06、AUTH-03/04 |
| D08 `postgres_version_dedicated_database_roles_tls` | psycopg 驱动、pool_pre_ping；无自动建表 | ①同主机专用 PG 实例，迁移/应用两个角色；②共享 PG 的独立数据库 | ①；迁移角色有 DDL，应用角色只有 DML；本机回环连接可不启用 TLS，跨主机时必须启用 TLS | 隔离最彻底；PG 是 D 级必需设施，无法省略 | 负责人指定的受支持 PG 版本（**本文不假设已部署**） | 否 | AUTH-*、MULTI-*、RECOVERY-01 |
| D09 `migration_and_tenant_bootstrap_operator` | Alembic 读取 `LAB_DATABASE_URL`，没有该变量时回退到 SQLite；PG 租户需另建；无租户管理入口 | ①先补租户管理 CLI；②DB 负责人手写受控 SQL | ①（G7）；迁移由 D01 负责人执行并校验 head `0004_api_keys` | 停用/恢复租户是 OIDC-05、AUTH-04 的操作步骤，需要可审计、可重复 | 迁移角色凭据（运行时注入） | 是，G7 | OIDC-05、AUTH-01/04、RECOVERY-01 |
| D10 `worker_launcher_instances_and_lease_policy` | 仅有内部 `process_next(context, owner)`；租约 300 秒，无 heartbeat；无常驻 worker | ①实现最小 worker CLI（租户白名单、owner、单次/循环）；②测试脚本直接调用内部 API | ①（G5）；每 worker 使用唯一 owner，租约保持 300 秒 | ②绕过可信调度边界，不能作为部署证据 | 两个 worker 进程 | 是，G5 | AUTH-04、MULTI-01/03/04 |
| D11 `artifact_shared_storage_and_acl` | FileArtifactStore 本地根目录；metadata 按租户过滤；摘要校验 | ①同主机共享本地目录；②网络共享存储 | ①；目录只允许服务账号读写，不由任何 HTTP 静态路由暴露 | 与 D03① 同主机配套，无需新增设施 | 专用目录及 OS ACL | 否 | AUTH-02、MULTI-03/04、RECOVERY-01/02 |
| D12 `secret_injection_reference_policy_no_values` | 环境变量读取；env 模板只放占位符；pepper 要求至少 32 字节 | ①服务进程环境（由负责人在主机上设置、不入库）；②专用 secret 管理器 | ①；证据只记录引用编号；OIDC-only 时不启用 api_key 模式，除非执行 AUTH-03 的 key 子项 | 不新增设施；秘密不经过本仓与证据 | 主机账户隔离 | 否 | 全部；AUDIT-01 |
| D13 `audit_correlation_retention_and_access` | 仅请求级 JSON；无 subject/tenant/实例/worker 事件；无 append-only 存储 | A HMAC 主体哈希+有效租户哈希+可信 request ID；B 明文 subject；C 保持请求级 | **A**（G1），见 §5；日志保留 30 天，只有负责人可读 | 满足归因且不在日志存储可关联的明文身份 | 日志目录 ACL；哈希盐作为秘密引用注入 | 是，G1 | AUDIT-01/02/03 |
| D14 `backup_restore_location_rpo_rto_and_owner` | 只有 SQLite 备份 helper；无 PG 备份 | ①PG 自带逻辑备份工具+制品目录快照，恢复到新库；②物理备份/PITR | ①；RPO=测试前备份点；RTO 由负责人定，建议 1 个工作日内 | 测试数据量小，逻辑备份最简单 | 备份存放目录、空恢复目标库 | 否 | RECOVERY-01（P 的准入） |
| D15 `exact_resource_inventory_and_cleanup_owner` | 材料脚本只做 dry-run；无 exact-ID 清理工具 | ①补 exact-ID 清理工具（事务、回滚、双人复核）；②负责人手工逐条处理 | ①（G8）；inventory 由执行者实时登记，清理由 D01 负责人复核 | 计划禁止前缀/全表删除，手工清理难以证明零遗留 | 受控 inventory 存放位置 | 是，G8（运维脚本） | RECOVERY-02、所有 C2 |
| D16 `a2_execution_boundary_no_untrusted_workloads` | 当前 worker 只运行内置 StubLabJudge 基准，不执行用户代码 | ①仅合成 fixture，明确不开放不可信执行；②同时推进 A2 | ①；A2 另行验收 | 与计划 §8 一致 | 无 | 否 | 所有 D 用例的边界 |

## 3. 关键决策一：角色与身份失效时限（D07）

### 当前实际行为（代码事实）

| 事件 | OIDC 旧令牌 | API key | 排队/运行中任务 |
|---|---|---|---|
| 角色降低（IdP 改属性） | 在 `exp + 30s` 之前仍按旧 roles 授权；新令牌按新角色 | 角色签发后不可改；只能撤销后重发 | 不受影响：run 不记录提交者，worker 不检查提交者角色 |
| 账号禁用（IdP） | 同上，直到过期；产品不知道 IdP 状态 | 不适用（key 不绑定用户）；需另外撤销该用户签发的 key | 不受影响 |
| key 撤销 | — | 下一请求在任意实例被拒（每次查库；多实例未现场验证） | 不受影响 |
| 租户停用 | 下一请求 403（身份有效但租户不可用） | 同左 | 下一个检查点（EVALUATING 前或提交元数据前）失败并清理制品；进行中的内存评估不被中断 |
| 最大令牌寿命 | 由 IdP 决定；产品不检查 `exp-iat` 上限 | TTL 1～365 天 | 租约 300 秒 |

### 目标要求（建议，未批准）

1. **OIDC 角色降低 / 账号禁用**：access token TTL 建议 10 分钟；产品侧最长寿命建议上限 15 分钟（G3，拒绝 `exp-iat` 超限的令牌，防止 IdP 误配成长寿命令牌）；失效上限 = 令牌剩余寿命 + 30 秒，最坏约 10.5 分钟。**不承诺即时失效**；如负责人要求即时失效，则 OIDC-06 按计划记 blocked，并另立 introspection 或撤销表实现任务（需要新设施或数据表，不在最小修复内）。
2. **API key**：测试 campaign 的 key TTL 建议 1～7 天；撤销目标为“撤销事务提交后，两实例的下一请求都拒绝”。
3. **租户停用**：新请求立即拒绝（提交后）；运行中任务在**下一个检查点之后不得产生可读报告或 COMPLETED 状态**，截止点最迟为一个租约（300 秒）。进程内计算继续运行的时间不计为“已失效”，这属于 A2 的进程回收范畴。
4. **已排队任务的归属**：建议将 run 视为租户资产，提交者降权或禁用不自动取消；需要时由租户 admin 显式取消。前提是 G4 记录提交者，否则无法按用户定位 run。

## 4. 关键决策二：公钥切换窗口（D06）

**当前能力**：启动时读取单个 PEM 文件；运行中修改文件不生效（材料测试 `test_static_public_key_rotation_requires_new_app_instance` 已证明）；不支持新旧公钥并存、`kid`、JWKS 或刷新。文件缺失时启动失败（`read_bytes` 抛 OSError）；**文件存在但 PEM 无效时的行为未验证**：启动时不解析密钥，推断会推迟到首个请求才报错，可能表现为 500 而不是启动失败。

**缺口**：①无双钥重叠，因此无法零中断轮换；②启动时不做 fail-fast 公钥校验；③readiness 不反映密钥状态；④日志不记录公钥指纹，只能靠运维记录。

**建议方案 A（维护窗口切换，未批准）**：

1. 事先记录旧公钥文件的 SHA-256 指纹，并保留旧公钥文件用于回滚；公布窗口，建议 15 分钟（大于建议的 10 分钟 TTL 加上重启时间）。
2. 停止测试流量 → IdP 切换到新签名密钥 → 替换所有实例的公钥文件 → **全部实例**重启 → 确认所有实例的文件指纹与启动时间一致。
3. 验收时复测四格：旧钥令牌在新实例 401，新钥令牌在新实例 2xx（OIDC-04）。窗口内出现的 401 属于预期，不计为失败。
4. **失败与回滚**：任一实例启动失败或新令牌被拒 → IdP 恢复旧签名密钥 → 恢复旧文件 → 全部重启 → 确认指纹 → 复测旧钥令牌可用。禁止出现实例间密钥不一致的滚动状态。

如负责人要求零中断轮换（方案 B），OIDC-04 保持 blocked，直到 G2 完成。JWKS 自动拉取（方案 C）按 ADR 0007 属于后续运维增强，不在本轮建议内。

## 5. 关键决策三：审计归因（D13）

**当前**：request 可以按 request_id、路由、状态码关联；主体、有效租户、认证方式、实例、worker 事件都没有记录；request_id 可由客户端伪造；project 行存明文 `created_by=subject`，run 行没有提交者；制品通过 tenant_id+run_id 关联到 run。401 时产品尚未得到可信身份，因此不应解析未验证的令牌。

**目标关联链（建议）**：

| 环节 | 应记录（建议） | 不得记录 |
|---|---|---|
| HTTP 请求 | 服务端生成的 `request_id`；客户端值只作 `client_request_id`（清洗后）；`instance_id`；`auth_method`；认证通过后的 `subject_hash`=HMAC(盐, iss+sub)、`tenant_id_hash`（取自已验证 Principal，即有效租户）；`decision`（authn_failed/permission_denied/tenant_denied/not_found/allowed）；`permission`；资源 ID（project_id/run_id） | Authorization 头、令牌或其任何片段、请求/响应正文、报告内容、明文 IdP 属性 |
| run 创建 | run 行增加 `created_by`（与 project 一致，存 Principal.subject；API key 为 `api_key:<key_id>`）；日志只写哈希 | 令牌 |
| worker 执行 | `run_id`、`tenant_id_hash`、worker `owner`、`fencing_token`、`attempt`、阶段与结果（claim/evaluating/committed/failed/tenant_denied） | 评估正文、提示词 |
| 制品 | `artifact_id`、`run_id`、`sha256`、size；通过 run 行追溯到 created_by | 制品内容 |

执行主体区分为：**请求主体**（subject_hash）、**执行主体**（worker owner），以及两者共同的**有效租户**。关联链是 request_id → run_id → owner/fencing → artifact_id/sha256。HMAC 盐是秘密，按 D12 注入且只记录引用；审计员在受控环境中用盐重新计算哈希来确认某个主体，日志本身不可逆。

实施说明（G1）：上表中“HMAC(盐, iss+sub)”在实现时改为按 `Principal.subject` 计算。理由是当前每个部署只配置一个 issuer，而且 run 的 `created_by` 只存 subject；只有按同一个值计算，worker 事件的 `submitted_by_hash` 才能和 HTTP 事件的 `subject_hash` 直接比对。API key 主体本身带 `api_key:` 前缀。以后如果支持多个 issuer，需要把 issuer 也纳入哈希输入，并同步迁移 `created_by` 的语义。

## 6. 推荐组合（自有本地/内网测试环境；全部为建议）

单台负责人提供的内网测试主机：同一个 venv 运行 2 个 uvicorn API 进程（不同端口、各自 TLS、各自 JSON 日志文件）+ 2 个 worker 进程（G5 完成后）+ 1 个专用 PostgreSQL 实例（迁移/应用角色分离）+ 本机共享制品目录（OS ACL）+ 1 个测试 IdP realm。不新增网关、消息队列、secret 管理器或集中日志平台。仅认证模式 `oidc`；只有在 AUTH-03 的 key 子项期间才启用 `api_key+oidc`。

建议数值：OIDC access token TTL 10 分钟，产品最长寿命 15 分钟（G3），leeway 30 秒（现值）；公钥切换窗口 15 分钟；租户停用截止点 = 下一检查点且不超过 300 秒租约；campaign key TTL 不超过 7 天；日志与证据保留 30 天（与制品默认保留一致）；RPO = 测试前备份点，RTO 1 个工作日。

**仍须新增的设施**：测试 IdP（若负责人没有现成的）、专用 PostgreSQL、测试主机与内网证书。这些是 D 级验收的必要条件，无法再压缩，也不能用 SQLite 或离线签发代替。

## 7. 19 项真实部署验收映射

按计划原预期执行，不降低要求。“类别”指在负责人确认 §8 问题后的状态。

| 验收 | 相关决策 | 类别 | 说明 |
|---|---|---|---|
| OIDC-01 | D01-D05、D12 | W | 签名/算法校验已具备 |
| OIDC-02 | D04、D05 | W | 需要 IdP 能签发错误 iss/aud，或经受控离线构造（签名有效） |
| OIDC-03 | D03、D04、D07 | W（G3 为建议增强） | 缺失 claims、过期、leeway 已具备；若负责人批准“产品强制最长寿命”，该子项先做 G3 |
| OIDC-04 | D06 | W（方案 A）/ F（方案 B → G2） | 方案 A 下的预期窗口 401 须事先批准 |
| OIDC-05 | D05、D09 | F（G7） | 停用/未知租户子项需要受控的租户状态操作 |
| OIDC-06 | D04、D07 | W（方案 A）/ B（要求即时失效） | 旧令牌在 TTL 内保留原角色是已知行为，须按批准上限判定 |
| AUTH-01 | D08、D09、D11 | F（G7） | PG 下需要先创建两个测试租户 |
| AUTH-02 | D08、D11 | F（G5、G7） | 需要 worker 产生已完成 run；直链检查依赖 D11 |
| AUTH-03 | D05、D12 | W（租户就绪后） | key 签发/撤销 CLI 已有；租户依赖 G7 |
| AUTH-04 | D07、D09、D10 | F（G5、G7） | 需要 worker 与租户状态切换；截止点按 §3 |
| MULTI-01 | D08、D10 | F（G5） | 无常驻 worker |
| MULTI-02 | D03、D08 | F（G6） | 推断并发同键会 500；须先修复再验收，不可放宽预期 |
| MULTI-03 | D10、D11 | F（G5） | 需要可暂停的 worker；无 heartbeat 集成，租约固定 300 秒 |
| MULTI-04 | D02、D03、D10、D11 | API 部分 W；worker 部分 F（G5） | 整项需两部分都通过 |
| AUDIT-01 | D03、D12、D13 | W（G1 已提供 `instance_id`，2026-09-29） | 令牌/正文不入日志已有 L0 证据；G1 新增 L1 canary 测试 |
| AUDIT-02 | D13 | W（G1+G4 已实现，L1 本机通过，2026-09-29；D 级仍未执行） | 原为 F；部署时需注入 `LAB_AUDIT_HASH_KEY`，并用两个真实测试账号复测 |
| AUDIT-03 | D13 | B | 产品无 append-only 审计或审计查询路由；需要负责人决定由产品还是外部日志设施承担；不得以普通文件日志冒充 |
| RECOVERY-01 | D08、D14 | W（且为其他 D 用例准入） | 由 DB 负责人使用 PG 工具，产品无需改动 |
| RECOVERY-02 | D15 | F（G8） | 计划禁止模糊或全表清理 |

汇总（共 19 项，G1+G4 完成后于 2026-09-29 更新）：等环境即可执行 W 的 8 项（OIDC-01/02/03、OIDC-04 与 OIDC-06（均已批准方案 A）、AUDIT-01、AUDIT-02、RECOVERY-01）；W 但有依赖或部分阻塞的 2 项（AUTH-03 依赖 G7 建租户；MULTI-04 的 worker 部分依赖 G5）；需先完成修复 F 的 8 项（OIDC-05、AUTH-01/02/04、MULTI-01/02/03、RECOVERY-02）；被产品能力阻塞 B 的 1 项（AUDIT-03）。评审时的原始统计是 W 6 / 部分 3 / F 9 / B 1。**以上都不代表真实验收已执行。**

## 8. 能力缺口与最小修复任务（本轮只记录，不实施）

| ID | 涉及文件 | 行为变化 | 兼容风险 | 测试与验收标准 |
|---|---|---|---|---|
| G1 = DEP-AUTH-03 审计归因 | `api/app.py`（`_observe_response`、principal 依赖把 Principal 写入 `request.state`）、`observability.py`（字段白名单增加 subject_hash、auth_method、decision、permission、instance_id、client_request_id）、`api/server.py`（注入盐引用与实例 ID）、`service.py`（worker 事件日志） | 认证后事件带主体/租户哈希；request_id 由服务端生成，客户端值另存；worker 输出阶段事件 | 日志消费方字段增加；响应头 X-Request-Id 语义改变（需在变更说明中写明）；未配置盐时应拒绝启动还是省略哈希，需要决定（建议拒绝，local 模式除外） | 两个账号执行相同拒绝操作时哈希不同且稳定；401 不含身份字段；canary 令牌/正文在所有日志中计数为 0；伪造 X-Request-Id 不能成为主 ID；worker 事件可串联 run→artifact；Ruff/strict mypy/A0 回归 |
| G2 = DEP-AUTH-01 多公钥并存 + 启动校验 | `auth.py`（接受公钥列表，按 `kid` 选择或逐个尝试）、`server.py`（例如 `LAB_OIDC_PUBLIC_KEY_FILES`，启动时解析每个 PEM） | 同时认新旧钥；无效 PEM 启动失败；日志记录公钥指纹 | 保留单文件变量的兼容；逐个尝试增加验签开销；`kid` 缺失时的策略 | 旧/新/第三方钥三组令牌；无效 PEM 启动失败；单文件配置回归不变；OIDC-04 四格 |
| G3 令牌最长寿命/leeway 配置 | `auth.py`（`max_token_lifetime`，拒绝 `exp-iat` 超限）、`server.py`（环境变量，默认保持现行为或按批准值） | IdP 误配长寿命令牌时拒绝 | 默认启用会拒绝现有长寿命令牌，建议仅在显式配置时启用 | 边界值 ±1 秒；未来 iat；leeway 0/30/300；OIDC-03 |
| G4 run 提交者 | `storage/models.py`、新迁移 `0005`（可空 `created_by` 列）、`domain/entities.py`、`run_repository.py`、`application/authorized.py` | run 记录请求主体；为 G1 提供归因 | 新增可空列，向后兼容；旧行为 NULL；迁移须先在备份上演练 | 迁移 up/down 于 SQLite 与测试 PG；幂等返回原 run 不改 created_by；跨租户负例回归 |
| G5 = DEP-MULTI-01 worker 入口 | `cli.py` 新命令（租户白名单、owner、`--once`/循环、停止信号）；可选接入 heartbeat | 提供可部署、可观测的 worker | 不改 `process_next` 签名；白名单须来自可信配置，而不是请求 | 两 worker 争抢同一任务只有一个完成；非白名单租户不被认领；停止信号不遗留租约；MULTI-01/03 |
| G6 并发幂等冲突 | `run_repository.py:create_idempotent`（捕获唯一约束冲突后回滚到 savepoint 并重新查询） | 同租户同键并发返回同一 run，不再 500 | 需要 savepoint；SQLite 与 PG 行为不同 | 先写能复现的并发测试（PG 或线程+SQLite）；A/B 同键互不影响；MULTI-02 |
| G7 租户管理入口 | `cli.py` 新命令 create/suspend/activate tenant（使用现有 `TenantRepository.set_status`，记录 operator） | PG 下可受控创建/停用租户 | 仅可信管理边界使用，不暴露 HTTP | 重复创建拒绝；停用后 API 403、worker 检查点失败；操作输出不含秘密 |
| G8 exact-ID 清理工具 | 新运维脚本（不入产品路径），输入受控 inventory | 按精确 ID 在事务内删除，默认 dry-run，执行前比对租户归属，失败则回滚 | 误删风险；必须拒绝前缀或通配 | 对合成库：多余/缺失/归属不符时全部拒绝；零遗留复查；其他租户摘要不变；RECOVERY-02 |

优先顺序建议：G1+G4（审计归因，负责人确认 Q3 后）→ G7 → G5 → G6 → G8；G2、G3 视 Q1/Q2 的回答决定。每项独立建任务、独立验收，不与 A1/A2 混合。

按负责人 Q1=A、Q2=A 的回答：G2 不再前置（OIDC-04 按维护窗口切换验收），但 G2 中的“启动时校验公钥”仍建议作为小修复；G3 仍建议实施，用来在产品侧强制已批准的最长令牌寿命（15 分钟），实施前需另行授权。

### 8.1 G1+G4 实施结果（2026-09-29，本机 L1；未部署、未提交）

- **G4**：`EvaluationRun.created_by`（可空，写入时校验 1～128 字符）、`evaluation_runs.created_by` 列、迁移 `0005_run_created_by`（batch 模式，可降级）。`AuthorizedLabApplicationService.create_run` 写入 `principal.subject`；`LabApplicationService.create_run` 新增可选关键字参数，旧调用方仍兼容（值为 NULL）。幂等重放保留原提交者；API 响应契约不变。
- **G1**：新增 `observability.AuditIdentityHasher`（HMAC-SHA256，域分离，截取 32 位十六进制，密钥至少 32 字节，repr 脱敏）。HTTP 事件新增 `instance_id`、`auth_method`、`subject_hash`、`tenant_id_hash`、`decision`（authn_failed/permission_denied/tenant_denied/allowed/not_found/conflict/invalid_request/rejected/error）、`permission`、`run_id`、`project_id`、`client_request_id`。401 不带任何身份字段。`X-Request-Id` 一律由服务端生成，客户端的安全值通过 `X-Client-Request-Id` 回显。worker 输出 `run_claimed`/`run_stage`/`artifact_committed`/`run_completed`/`run_failed` 事件，带 run_id、worker_owner、fencing_token、attempt、tenant_id_hash、submitted_by_hash 和制品 sha256；失败只记录类别（`tenant_denied`/`error`），不记录异常文本。
- **兼容变化**：`api_key`/`oidc`/`api_key+oidc` 模式缺少 `LAB_AUDIT_HASH_KEY` 或长度不足时拒绝启动（fail-closed）；disabled/local 模式不要求。`LAB_INSTANCE_ID` 可选，默认 `pid-<进程号>`，不合法时拒绝启动。有 3 个现有测试随之做了最小调整（见 TODO）。
- **证据**：[g1-g4-20260929](evidence/g1-g4-20260929/)。

## 9. 需要负责人回答的问题（最多 3 个）

> 2026-09-29 已回答：1=A、2=A、3=A。

1. **角色降低与账号禁用的失效上限**。A：短 TTL，上限约 10.5 分钟，不做即时撤销（**推荐**）；B：要求即时失效；C：接受 60 分钟 TTL。影响 OIDC-03/06、AUTH-03、IdP 配置以及是否需要 G3 或另立撤销实现；选 B 时 OIDC-06 先保持 blocked。
2. **公钥轮换方式**。A：15 分钟维护窗口，全部实例重启，窗口内的 401 属于预期（**推荐**）；B：要求零中断双钥并存。影响 OIDC-04 的判定和 G2 是否前置。
3. **审计归因级别**。A：日志记录 HMAC 主体哈希+有效租户哈希+服务端 request ID，run 行存明文提交者（**推荐**）；B：日志也存明文 subject；C：维持请求级，AUDIT-02 不做。影响 AUDIT-01/02/03 与 G1/G4 的范围；选 C 时 AUDIT-02 保持 blocked，不能标记通过。

其余决策（D01～D05、D08～D12、D14～D16）保持“建议”状态，不阻塞本评审。执行真实部署前，负责人须另外逐项确认并提供环境，届时再填写配置模板。

## 10. 检查记录

评审轮：文档一致性与 `git diff --check` 结果记录在 TODO 中；该轮未修改脚本，因此未运行测试。G1+G4 轮的测试与静态检查见 TODO 中的 “G1+G4” 条目。

## 11. 2026-09-30 当前代码复核与16项推荐

根HEAD `4235350fbd4d8858fbaac23f380e6cce87688d61`；Agent HEAD `74fbe58da54e5999acefaed3c572c46c831fe86e`。工作区已有未提交认证、任务、审计、迁移、测试与本文，不将它们当作本轮实现。开工全文及SHA-256保存在 [本轮证据](evidence/deployment-decisions-20260930/preflight.json) 与其 `before/` 目录；回滚只回退本轮文档差异。下文是**代码阅读结论**，未新跑权限测试，也不引用历史通过数字作为本轮结论。

当前支持单主机ASGI factory、SQLite开发路径和SQLAlchemy/psycopg PostgreSQL路径；仓内未提供常驻worker或集群编排。推荐先准备一台自有本地/内网测试主机，分阶段验证单实例，再在同主机运行两个API和两个可信worker；共享专用PG及本地制品根。IdP、PG、测试证书和主机均是**待提供条件**，不能假定现成。若没有IdP，先评审引入独立测试实例的成本，不能改用离线签名冒充真实OIDC验收。

源码依据：认证 [auth.py](../src/ai_agent_lab/auth.py)、启动 [server.py](../src/ai_agent_lab/api/server.py)、HTTP归因 [app.py](../src/ai_agent_lab/api/app.py)、HMAC及白名单 [observability.py](../src/ai_agent_lab/observability.py)、任务检查点 [service.py](../src/ai_agent_lab/application/service.py)、租约/取消 [run_repository.py](../src/ai_agent_lab/storage/run_repository.py)、主体传递 [authorized.py](../src/ai_agent_lab/application/authorized.py)、提交者迁移 [0005](../migrations/versions/0005_run_created_by.py)。

需要纠正的旧事实：run已有可空`created_by`，HTTP授权层从Principal传入，幂等重用不改原提交者；worker已有阶段/制品事件。HTTP已生成服务端request ID并将清洗后的客户端值单独回显，已记录可信主体与有效租户HMAC。认证部署必须配置`LAB_AUDIT_HASH_KEY`（至少32字节），API可配置`LAB_INSTANCE_ID`。源码迁移head已为`0005_run_created_by`，**未证明任何PG已迁移**。旧计划的0004与AUDIT-02“无归因”属于9月28日快照，执行时以本节为准；不改写历史证据。

16项与原JSON模板键逐一对应。下表所有推荐均**待确认**；描述秘密引用策略，不填真实值。G号保留既有任务标识；R号是本次补充的最小任务，见§16。必要环境以E号标识：E1授权主机/账号与负责人，E2独立真实测试IdP，E3专用PG及恢复目标，E4证书/时钟/可信进程管理与共享目录，E5受控证据、日志和备份位置。

| 决策 / 原模板键 | 当前实现 | 可选方案 | 推荐方案（待确认） | 理由与必要环境 | 代码缺口 / 验收 |
|---|---|---|---|---|---|
| D01 `test_environment_owner_and_authorization` | 代码不证明测试资源授权；已有合成清单 | 自有主机单负责人；独立运维；托管 | 单一负责人负责授权/停止/清理，列exact-ID与专用非生产资源；破坏性步骤由第二人或负责人独立复核 | 人少、边界可检查；E1，owner姓名/设备标识待填 | 无产品改动；19项全体准入，RECOVERY-02 |
| D02 `operating_system_and_runtime_versions` | pyproject规定Python范围/依赖；历史本机3.14.6非可复现部署保证 | 原OS新venv；另一OS；容器 | 首轮采用负责人可维护的自有OS，新venv按现有声明安装，固定实际依赖清单和Agent/shared提交及dirty摘要；两个实例一致 | 不选新运行栈；OS/Python具体版本待确认；E1 | 无直接代码缺口；全部证据头、MULTI-04。本轮不安装 |
| D03 `api_instances_proxy_tls_and_clock_sync` | ASGI factory；API instance_id可配置，默认pid；server request ID已实现；无TLS拓扑/网关配置 | 同主机两API直连TLS；反代TLS；多主机 | 分阶段1→2个API，固定端口和唯一稳定instance_id；内网直连时用现有ASGI TLS能力与受信测试证书，不加反代；仅回环本机练习可另批无TLS模式 | 足够验证多进程，不能证明多主机HA；时钟最大偏差建议5秒并实测；E4 | 部署证书/监听ACL待定；worker instance标签见R5；OIDC-01～06、AUTH-*、MULTI-02/04、AUDIT-01/02 |
| D04 `oidc_provider_issuer_audience_token_type` | 固定issuer/audience、sub/iat/exp；无discovery/introspection；不按token类型区分ID/access | 现有自有测试realm；新增测试IdP；本地自签 | 优先自有独立测试realm；没有则先批准一个隔离测试IdP，再选具体产品；只用专用API audience的access token | 避免预设厂商与已安装设施；离线token仅L1；E2 | 用audience隔离令牌，若ID/access同aud需R2；OIDC-01/02/03/05/06 |
| D05 `oidc_algorithm_claim_mapping_and_test_accounts` | 默认RS256；tenant_id字符串、roles字符串数组；角色来自签名claims | 默认claims+RS256；ES256；自定义claims | RS256+默认claims；A/B各V/O/A/D八个合成测试账号；tenant/roles仅IdP管理员维护，sub稳定且不可自行改 | 与现有配置最少差异；E2需映射和账号禁用能力 | 无新角色架构；R2关注OIDC与API-key身份命名空间；OIDC-01/05、AUTH-03 |
| D06 `oidc_public_key_distribution_rotation_rollback` | 单PEM启动读取；不看kid选钥，无并存/JWKS/刷新 | 维护停流全重启；双钥滚动；JWKS | 15分钟预算维护窗、停流全重启；在线旧/新钥并存窗口为0；详情§13 | 测试可接受停机，避免虚构刷新；E2/E4 | 推荐方案需R4启动校验；双钥才需G2，JWKS另案；OIDC-04、MULTI-04 |
| D07 `role_change_and_token_revocation_sla` | OIDC旧claims有效至exp+30s，无TTL上限；key逐次查库；租户/worker阶段检查，无实时中止 | 短TTL有界；即时撤销；长TTL | access TTL10分钟且产品强制exp-iat≤600秒（R1）；租户停用后新请求拒绝，旧请求/任务授权截止目标30秒（R3/G5）；用户降权不自动取消已提交租户任务 | 明确身份与租户资产语义；数字是目标不是现状；E2/E4；详情§12 | R1/R3/G5前置；即时用户撤销另案；OIDC-03/06、AUTH-03/04、MULTI-03 |
| D08 `postgres_version_dedicated_database_roles_tls` | psycopg/SQLAlchemy支持；PG不自动建表；未实测版本/锁/TLS | 同主机专用实例；共享实例独立数据库；SQLite | 自有同主机专用PG实例/库；迁移角色DDL，应用角色限必要DML；连接限回环，远程必验证TLS；恢复库独立 | D级多进程锁不可用SQLite替代；PG具体受支持版本/兼容性由负责人选并验证，不声明某版本已支持；E3 | 无另换存储；G6并发风险待复现；AUTH-*、MULTI-*、RECOVERY-01 |
| D09 `migration_and_tenant_bootstrap_operator` | Alembic env可退回SQLite；源码head0005；无租户管理CLI，仓储有set_status | 受控仓储/SQL步骤；最小管理CLI | 专人用迁移角色，先证明目标dialect为PG，备份新库演练0005后建A/B；后续G7提供审计化create/suspend/activate入口 | 不把LAB_TENANT_ID当PG建租户；E3 | G7，禁止silent SQLite回落；OIDC-05、AUTH-01/03/04、RECOVERY-01 |
| D10 `worker_launcher_instances_and_lease_policy` | process_next可信内部context/owner；300秒租约，仓储heartbeat但service未接入；无runner | 受控单次调用；最小worker CLI；另建队列 | G5提供单次/循环、可信tenant白名单、唯一owner、停止信号；两worker同PG；首轮合成任务预算≤60秒、租约300秒；超过预算不开放长任务 | 不加消息队列；租约不是执行超时；E4 | G5+R3需30秒授权停用检查/停止，长任务heartbeat另议；AUTH-04、MULTI-01/03/04 |
| D11 `artifact_shared_storage_and_acl` | 本地FileArtifactStore、tenant/run metadata过滤和hash核验 | 同主机共享根；网络共享；对象存储 | 专用同主机目录；只服务账户读写、负责人读恢复；无静态HTTP直链；两个实例同根，campaign与exact-ID登记 | 与同主机方案配套、不新增设施；E4 | 停用检查与commit竞态R3；非共享挂载不能过MULTI-04；AUTH-02/04、MULTI-03/04、RECOVERY-01/02 |
| D12 `secret_injection_reference_policy_no_values` | env读OIDC配置/pepper与必需audit key；公钥文件非私钥 | 进程env受控注入；secret平台 | 负责人在主机运行时注入；仓库只记录引用；audit key所有实例一致、≥32字节；OIDC常规模式，API-key子项单独开组合模式；不把env写进日志/进程参数 | 不新建secret平台；OS账号/进程环境权限属E1/E4 | 密钥epoch/轮换策略R5，禁止哈希密钥当普通“盐”；全部、AUTH-03、AUDIT-01/02 |
| D13 `audit_correlation_retention_and_access` | 已有请求主体/tenant HMAC、request/instance/permission/decision；run提交者、worker owner/fencing和artifact事件；无append-only/保留器 | 现有脱敏归因+受控保留；明文主体日志；仅请求日志 | 保留现有HMAC方案，补§14缺口；30天受控测试证据/日志保留建议，负责人只读归因；原始run created_by作为受限DB身份映射 | G1/G4已落代码，不重做；E5负责访问/归档/完整性 | R2/R5身份域与worker标签；AUDIT-03需环境保留/受控封存，不能声称防管理员篡改；AUDIT-01/02/03 |
| D14 `backup_restore_location_rpo_rto_and_owner` | 仅SQLite helper，不能承担PG/PITR | PG逻辑备份+停写文件快照；物理/PITR | 首轮停所有测试写入后PG逻辑备份+制品一致快照，恢复到新空库/目录；RPO=该备份点，RTO目标1工作日（待确认、实测） | 小合成数据适用；无生产SLA；E3/E5 | 运维选择对应版本工具，不需新产品备份器；RECOVERY-01、MULTI-04 |
| D15 `exact_resource_inventory_and_cleanup_owner` | 现材料仅dry-run，无真正删除工具 | 人工exact-ID逐项；G8专用清理工具 | 首轮允许经负责人复核的人工exact-ID清理，先停worker/撤销测试身份、验证备份，按FK依赖列计划再执行；重复运行才做G8 | 不因缺CLI扩大源码；前缀不是所有权证据；E1/E5 | G8可选运维任务，默认dry-run、不得触达他campaign；RECOVERY-02和全部清理步骤 |
| D16 `a2_execution_boundary_no_untrusted_workloads` | 内置StubLabJudge；subprocess限制不是生产沙箱 | 合成内置fixtures；不可信代码/A2 | 仅已有合成fixtures，不开放任意代码/目标/外部模型；A2独立审批实际运行时及进程树/文件/网络隔离 | 与当前阶段相称；不存在“A2已通过”推论 | A2不在本轮，必须独立验收；全部19项边界、MULTI-03 |

## 12. 失效时限：当前事实与待确认目标

失效基准T必须分别记录：IdP修改已生效且已停止旧权限新令牌签发/刷新；数据库停用或撤销事务已提交。不能用点击按钮时间代替T。受信refresh token能否再换取旧roles由真实IdP执行OIDC-06证明。

| 事件 | 当前代码事实 | 推荐目标（待确认）与剩余工作 |
|---|---|---|
| 用户降权/账号停用 | 产品不查询IdP状态；旧access token仍按旧claims，只有exp/leeway；没有最长TTL限制 | IdP禁止继续签发旧权限token，TTL≤600秒，产品R1强制相同上限。自T起最坏≤600+30+实测时钟偏差δ秒；若δ≤5秒，预算≤635秒。旧文“10.5分钟”仅δ=0的近似，不作真实上限 |
| API key撤销 | 每请求查DB revoked/expiry/tenant；key主体为api_key:key_id，不自动等同IdP用户 | T之后启动认证的下一请求拒绝，不设缓存；已认证在途请求不受撤销检查保护。需要即时中断在途时另开撤销再检查任务；用户停用还需按受控inventory撤销关联key，不能声称自动同步 |
| 租户停用后的新请求/领取 | 服务入口查active；OIDC有效身份业务拒绝403；API-key认证JOIN active会先拒绝401；worker认领前查active | T以后新事务拒绝；两类401/403都有效且不暴露状态。不是所有接口均403。R3需要处理检查与提交的竞态，实测两实例 |
| 停用时在途请求、任务、制品 | 阶段检查，不实时中止；读报告检查与文件读取之间也有窗口；无检查周期/计算时限；lease过期只限制状态写入，不能终止计算或保证文件及时消失 | 目标T+30秒后不再有授权提交/制品发布；采用可测检查/取消与提交序列化（R3/G5），已在T前开始的请求须记录其边界。确认前记代码阻塞，**不得把300秒租约当作停用上限** |
| 提交者降权/停用后已入队任务 | run已有created_by但worker不检查提交者当前角色；任务按租户授权 | 建议任务为提交时授权的租户资产，保持运行；admin按run ID显式取消。若要求用户停用连带任务失效，需用户状态映射/撤销传播及可信worker再授权，另案，不能从created_by推断已有能力 |
| 取消与进程 | DB取消清lease，陈旧worker转换失败，异常路径清理已写制品 | 授权状态与制品一致性属MULTI-03；杀死完整进程树属A2。30秒是待实现的授权停止目标，不是已实现的宿主隔离或进程回收保证 |

推荐的R1上限为600秒，**不同于旧建议产品允许15分钟token**。若仍允许900秒则最坏是930+δ秒，不能同时宣传10.5分钟上限。这项差异必须由负责人重新确认。当前没有任何上述新数字的部署证据。

## 13. 公钥切换、并存、刷新和回滚

推荐仍采用单钥维护切换，15分钟是停机预算而非保证。停止测试入口/发token流量、暂停worker新认领，逐实例记录旧公钥指纹、版本、配置引用和可回滚备份；确认非秘密公钥来源可信。先做R4密钥格式/算法可用性启动校验与不泄密readiness验证，当前readiness仅SELECT 1及目录存在，不能证明OIDC可用。

切换顺序：冻结入口→IdP新签名key启用→所有API替换单个PEM→全部重启→逐实例用真实测试账号新token正例/旧token拒绝和错误签名负例→记录指纹/启动时间→恢复流量。停止阶段保留401证据，按**事先确认的维护窗口**判定；窗口之外401或新token失败是故障，不把所有401一概豁免。

**新旧密钥在线并存窗口为0**；旧公钥仅受控保存在回滚材料，不能配置为同时信任。刷新机制只有重启重新读文件；无kid选择/JWKS/后台刷新。维护窗内禁止两实例对外保持不同钥状态；不以滚动重启声称无缝轮换。未来双钥方案G2才允许建议上限635秒的旧token排空窗口，并要求按kid绑定key/算法、防止未知kid回退；该数值及实现均待批准。JWKS方案另需可信HTTPS来源、缓存上限、未知kid刷新限流、失败关停策略，当前无此能力，不列最小方案。

回滚触发：任一实例新token正例失败、指纹不同、启动/校验失败，或超15分钟预算仍未验证；保持入口关闭，协调IdP恢复未泄露旧签名key、恢复旧公钥并全部重启，复测旧正例/新拒绝和两实例一致性。**因旧私钥泄露/失陷而轮换时禁止恢复旧信任**；停止环境并进行新钥恢复，不为恢复绿色结果放宽验签。私钥不由本项目收集；IdP管理者只提供受控操作回执和公钥指纹。

## 14. 审计关联要求与当前剩余缺口

| 环节 | 当前存在的字段/来源 | 推荐要求（待确认） |
|---|---|---|
| 请求者与有效租户 | 认证成功后的Principal→subject_hash、tenant_id_hash、auth_method；服务端request_id，客户端值另存；API instance_id/permission/decision | 有效租户只来自验证Principal，不接受客户端tenant override。401缺可信身份时不解析JWT作归因；API-key停用401也可能无主体，只以request/instance追踪 |
| 任务提交 | HTTP建run事件关联request_id/run_id，数据库created_by保存subject；旧run可能NULL | 请求可多次幂等重用同run，日志关联为多对一；不可覆盖原提交者。NULL标unknown，禁止猜测回填；非HTTP受信调用必须显式提供身份 |
| 后台执行 | run_id、worker_owner、attempt、fencing_token、submitted_by_hash、tenant_id_hash及阶段/失败类别 | 执行主体worker_owner与请求者submitted_by_hash分开；owner不是用户权限凭据。R5补稳定worker instance_id/启动epoch；可信白名单与owner归属须由G5验证 |
| 制品 | artifact_id/run_id/format/sha256/size，metadata连接tenant/run；artifact_committed事件 | 从请求→run→owner/fencing→artifact复核租户归属与摘要，不在日志写内容；取消/停用拒绝与残件清理亦须留结果/回执 |
| 哈希身份域 | 当前HMAC按`subject\0subject`与`tenant\0tenant`域区分；仅subject，没有issuer/auth_method；所有实例共用key | 单issuer部署下先限定OIDC subject不可与api_key:key_id命名空间重叠；若无法保证则R2加入issuer/auth_method并同步worker归因。此为代码推断的碰撞风险，未现场复现 |
| 秘密与留存 | 白名单formatter；不复制异常正文；无长期保留/不可篡改设施 | 不记录Authorization/token片段/正文/DSN/私钥；HMAC key是秘密。记录key版本引用/epoch而非值，轮换需明确关联断点。先负责人受控目录+每次封存摘要/清理回执；不宣称防特权管理员篡改 |

G1/G4当前源码已有，本轮不再列为“待实现”或重跑其历史测试。真正剩余的是可信worker启动、身份命名空间、实例标签、日志链完整性及ACL/保留/封存证据。AUDIT-03若要求抵抗宿主管理员的append-only，普通目录+摘要不足，必须单列外部不可改写存储或产品审计设施决策并保持阻塞；不能缩减原验收预期。

## 15. 19项部署验收→决策、阻塞和顺序

共同前置为D01/D02/D12/D16；下表逐项再列主决策，所有状态均**未执行**。E号是环境未提供，G/R号是代码或受控运维能力不足；“未复现”风险须先复现再决定修复，不视为确定产品故障。无阻塞不等于通过。

| 验收项 | 主决策 | 环境阻塞 | 代码/能力阻塞 | 状态 |
|---|---|---|---|---|
| OIDC-01 | D03,D04,D05 | E2,E4 | 启动key有效性R4；请求验签已有代码 | 未执行 |
| OIDC-02 | D04,D05 | E2 | 错iss/aud样本须签名有效且受控，不能用本来验签失败的样本证明 | 未执行 |
| OIDC-03 | D03,D04,D07 | E2,E4 | 强制600秒上限R1；时间/claims负例仍须实测 | 未执行 |
| OIDC-04 | D03,D06,D12 | E2,E4 | 推荐维护方案R4；零停机方案G2或JWKS另案 | 未执行 |
| OIDC-05 | D04,D05,D09 | E2,E3 | G7或受控可审计管理步骤；R2身份域取决IdP映射 | 未执行 |
| OIDC-06 | D04,D07 | E2 | R1；即时失效若被选择需额外撤销机制 | 未执行 |
| AUTH-01 | D05,D08,D09 | E2,E3 | G7或受控管理步骤；跨租户过滤已有代码 | 未执行 |
| AUTH-02 | D05,D08,D11 | E2,E3,E4 | 跨租户过滤已有代码；停用读报告竞态另属R3/AUTH-04 | 未执行 |
| AUTH-03 | D05,D07,D09,D12 | E2,E3 | 需要管理步骤、真实角色传播/key撤销；不假设用户key自动关联IdP | 未执行 |
| AUTH-04 | D07,D09,D10,D11 | E2,E3,E4 | R3、G5及租户管理步骤；30秒目标当前不保证 | 未执行 |
| MULTI-01 | D08,D09,D10,D13 | E3,E4,E5 | G5，真实PG skip_locked/租户/owner证据 | 未执行 |
| MULTI-02 | D03,D08,D09 | E3,E4 | G6先复现unique冲突可能500，再最小修复 | 未执行 |
| MULTI-03 | D07,D10,D11,D16 | E3,E4 | G5/R3、可控暂停/租约时序；A2进程树不在本轮 | 未执行 |
| MULTI-04 | D02,D03,D06,D08,D10,D11 | E3,E4 | G5、迁移0005及重启证据；不能只测API部分算整项通过 | 未执行 |
| AUDIT-01 | D03,D10,D12,D13 | E4,E5 | G1字段已有；R5和G5完整worker链、全链canary验证 | 未执行 |
| AUDIT-02 | D05,D10,D12,D13 | E2,E4,E5 | G1/G4已有；R2命名空间/R5标签及真实账号归因 | 未执行 |
| AUDIT-03 | D01,D12,D13,D15 | E1,E5 | 缺完整ACL/轮转/保留/丢失证明；抗管理员篡改要求需独立设施，不以日志文件替代 | 未执行 |
| RECOVERY-01 | D08,D09,D11,D14 | E3,E4,E5 | PG工具/恢复目标和0005演练未提供；SQLite helper不适用 | 未执行 |
| RECOVERY-02 | D01,D09,D11,D14,D15 | E1,E3,E5 | 审核后的exact-ID手工方案或G8；缺可审查清理计划则停止 | 未执行 |

执行顺序（以后另次授权）：

1. 确认16项与负责人/资源边界，确定E1～E5；完成R1/R3/R4和G5等所选目标的前置任务。生产隔离仍独立A2。
2. 固定源码/依赖/配置引用，检查PG dialect、迁移0005与A/B合成租户，准备exact-ID清理预览。初始备份→最小测试身份/权限状态→RECOVERY-01恢复到新目标并复测授权状态；恢复通过后才做竞争/重启/清理等故障测试。
3. OIDC-01/02/03/05正反例→AUTH-01/02/03→OIDC-06→OIDC-04维护切换，保留窗口外故障与回滚证据。
4. AUTH-04→MULTI-01/02/03/04（先有可控runner与同步时序）。不满足30秒停用目标或出现跨租户允许则停，不以延长租约掩盖。
5. 审计日志从第一步全程收集，最后集中执行AUDIT-01/02/03完整性/归因/保留核对；缺任何身份域或实例链不能通过。
6. 停流/停worker、保留脱敏证据和可恢复备份，再RECOVERY-02按exact-ID清理并验证零遗留/其他租户不变；没有授权或备份则只预览。19项分别附D级证据后才评定，不改现有not_run模板。

## 16. 最小任务与不确定项

| 任务 | 当前结论 | 最小后续动作 / 关联 |
|---|---|---|
| G1/G4 | 已有工作区实现，部署未验收 | 保留代码/迁移/测试；只在真实环境复核AUDIT-01/02，不重复实现 |
| R1（细化G3） | 没有token TTL上限 | 明确600秒与leeway30秒，参数/边界/未来iat校验及兼容行为；OIDC-03/06。确认目标后独立修复 |
| R2 | token类型/主体域未区分，风险来自读代码，未复现 | 先用合成ID/access同aud和OIDC sub=api_key:key_id记录复现；不能通过IdP约束时，才补最小类型/命名空间校验及worker关联；OIDC-05、AUDIT-02 |
| R3 | 停用/读报告/提交检查窗口无时间保证 | 用合成tenant和事务同步复现，定义停用与提交序列化、在途读/worker授权截止；不承诺终止宿主进程；AUTH-04、MULTI-03 |
| R4（拆出G2必需子项） | 单钥读取但未在启动解析/匹配算法，ready不检验 | 先复现无效/错误算法PEM行为，再最小fail-fast及不泄密配置/指纹证据；OIDC-01/04。不顺带实现多钥/JWKS |
| R5 | API instance标签已有；worker只owner，哈希key无epoch字段 | 确认唯一owner是否足够关联主机/启动周期；不足再补稳定worker标签/配置摘要/哈希key版本引用；AUDIT-01/02。不引入集中审计产品 |
| G5 | 没有常驻worker启动器，service未heartbeat | 先最小可信白名单/owner/单次运行与停止入口；有界fixtures配合R3；长任务heartbeat单独决定；MULTI-01/03/04 |
| G6 | 同键先查后插入可能unique冲突500，尚无本轮复现 | 先真实PG并发复现，成立再事务内最小冲突处理；MULTI-02 |
| G7 | 无租户管理CLI，不等于数据库负责人完全无法执行 | 首轮受控管理步骤可评审，重复性不足时补最小create/suspend/activate入口和操作者证据；OIDC-05、AUTH-04 |
| G8 | 无删除执行工具，现脚本dry-run | 首轮manual exact-ID清单可用，缺可核对步骤就阻塞；后续专用dry-run默认工具，不做通用删除器；RECOVERY-02 |
| G2/即时撤销/A2 | 推荐维护窗不要求多钥；即时撤销和生产隔离未实现 | 仅负责人选择更强目标才另立范围，不能推定已授权编码或新设施 |

优先级建议：先确认§17的目标→R1→R4→R3/G5（相互明确边界）→G6复现→环境准备与恢复演练。审计归因已有实现，下一步不是再做G1/G4。所有修复在本轮只列任务，不修改源码。

## 17. 集中待确认问题（3项，均未取得本轮确认）

1. **失效时限与任务语义**：A（推荐）access TTL≤10分钟、产品强制同上限，旧token最坏≤635秒（时钟偏差≤5秒）；租户在途授权停止目标30秒，提交者降权不自动取消租户任务。B即时用户/token/任务失效。C接受更长TTL与仅阶段检查、不承诺30秒。A需要R1/R3/G5；B增加撤销状态/传播与worker再授权；C降低目标且须明确风险，不自动降低原19项验收要求。
2. **公钥切换**：A（推荐）15分钟预算停流维护、全部实例重启，在线双钥窗口0，先R4校验。B零中断双钥，先G2。C要求JWKS自动刷新，另立缓存/限流/信任策略。A有测试停机；B/C增加实现和验收范围；旧钥失陷时都禁止回滚旧信任。
3. **测试规模与审计强度**：A（推荐）自有单主机分阶段1→2 API、两个可信worker、专用PG和独立测试IdP，沿用HMAC归因并做受控日志封存/30天保留。B多主机并要求抗管理员篡改审计。C暂不提供设施、仅评审与L1。A仍需逐项确认E1～E5、证书/ACL和R5等缺口，不能直接宣布AUDIT-03通过；B需额外共享存储/可信日志设施；C所有D级项目继续未执行。三选项都不等于本轮部署授权。

历史§9的“A/A/A”记录只覆盖彼时问题，本轮调整了产品TTL一致性、在途停用目标和环境/审计组合，不能据旧记录自动批准新推荐。其余决策仍须逐项确认；负责人答案不会自动触发资源创建、依赖安装、编码或部署。

## 18. 本轮文档检查

本轮只检查文档本地链接、16个模板键一一对应、19个验收ID/决策引用、未执行状态、推荐待确认标记及Git空白差异；不运行权限/部署测试，不安装工具。实际结果记录于 [checks.json](evidence/deployment-decisions-20260930/checks.json)，完整性见 [integrity.json](evidence/deployment-decisions-20260930/integrity.json)。旧基线与G1/G4数字不计入本轮结果。Git的全局ignore读取权限警告如仍出现如实保留，不更改用户配置规避。

现场结果：16个模板键与D01～D16一致，19个验收ID完整且全部未执行，3个负责人问题；24个本地文件引用无缺失，新增TODO章节锚点已核对。PowerShell文档检查exit0、`git diff --check` exit0，既有解释器执行 `../scripts/repair_links.py --check` exit0（只读）。首次文档检查因先读取尚未生成的checks.json自引用返回1，生成证据后复查通过，首次记录保留；不属于产品或部署失败。既有源码/脚本/测试/其他文档摘要无变化，仅本文和TODO新增内容；根仓干净，HEAD未变。
