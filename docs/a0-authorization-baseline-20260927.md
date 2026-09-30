# A0：现有权限与跨租户改动现场基线

日期：2026-09-27。**A0 本机权限基线验收完成。** 本轮没有复现需修复的权限缺陷，未修改产品源码。类型检查最初缺少工具，后通过独立临时目录中的固定版本 mypy 补齐。此结论只覆盖下述自建租户、合成数据与本机测试，不能作为 SaaS 多租户验收。

## 1. 起点与既有工作保护

- 工作目录：`<suite-root>`。
- 根仓：`4235350fbd4d8858fbaac23f380e6cce87688d61`，开工 status 干净，无 remote。
- Agent：`74fbe58da54e5999acefaed3c572c46c831fe86e`；origin `https://github.com/longyuanai/003AI-Agent-Security-Lab.git`。没有访问远端。
- 已阅读根 AGENTS、MODEL-HANDOFF，Agent README、CAPABILITIES、tech-spec、TODO、docs/CODEX_INSTRUCTIONS，以及身份 ADR-0005。在当前项目 src/tests/docs 下未发现额外 AGENTS.md；未将 archive 的旧规则当作新任务。

开工时已有修改：`.gitignore`、`README.md`、`docs/CODEX_INSTRUCTIONS.md`、`docs/TODO.md`、`docs/commercial-spec.md`、`docs/tech-spec.md`、`api/app.py`、`application/service.py`、`auth.py`、`domain/__init__.py`、`domain/entities.py`、`storage/auth_repository.py`、`storage/repositories.py`；未跟踪 `CAPABILITIES.md`、`docs/archive/`、`tests/test_tenant_isolation.py`。其中七个源码路径均以 `src/ai_agent_lab/` 为前缀。

修改文档前已将 Git 列出的原修改文件与 `tests/test_tenant_isolation.py` 按原始字节复制到新建系统临时备份目录，并记录 SHA-256。路径见 [preflight.json](evidence/a0-20260927/preflight.json)。该文件的 status 采集时已创建本轮证据目录，因此含该新增目录，不将它算作用户原有修改。所有上述旧文件在文档更新前的摘要均一致，见 [preserved-before-doc-update.json](evidence/a0-20260927/preserved-before-doc-update.json)；最终仅 README、TODO、tech-spec 追加/纠正本轮说明，原产品源码和旧 tenant 测试原样保留。回滚本轮应只移除新增测试/报告及本轮文档差异，不能对已有 dirty 文件执行整文件 Git 还原。

## 2. 对既有差异的复核

| 既有改动 | 当前作用 | 本轮证据与局限 |
|---|---|---|
| `TenantAccessError`、HTTP 403 handler | 缺失/停用租户统一返回 `tenant_access_denied` | 原 tenant 测试 + 新增六操作 × 两状态矩阵；不暴露租户状态/资源 ID |
| API key 签发查 active、认证 JOIN active tenant | 不给缺失/停用租户签发 key；停用后旧 key 不再认证 | 原签发/停用/过期/撤销负例现场通过 |
| 应用服务各入口 `_require_active_tenant` | 即使 Principal 已验证，仍检查租户生命周期 | 新增模拟已验证 OIDC Principal 的缺失/停用矩阵；不是实际 IdP 联调 |
| worker 在认领、评估落库、完成提交前查 active | 停用时阻止报告提交，异常路径清理制品并保留失败状态 | 新增评估后、制品写完后停用负例；检查另一租户 run 未变 |
| 完成 run 在提交事务内重新读取 | 完成后返回当前租户 run | 原完整 API→worker→report 测试现场通过 |
| `TenantRepository.set_status` 的 version 条件 | 拒绝陈旧生命周期写入 | 原状态转换测试现场通过；未覆盖 PostgreSQL 多进程竞争 |

没有将既有改动重新实现，没有合并或提交这些文件。

## 3. 授权路径表

角色：V=viewer、O=operator、A=admin、D=auditor。D 只有预留的 audit:read 权限，当前没有 audit HTTP 路由。

| 入口/操作 | 身份、角色与租户来源 | 服务/存储强制约束 | 拒绝结果及现场覆盖 |
|---|---|---|---|
| 商业路由公共前置 | `api/app.py` 读取 Authorization；APIKeyAuthenticator/OIDCAuthenticator → frozen Principal → TenantContext；不读客户 tenant header/query | HTTP `require_permission` + `AuthorizedLabApplicationService` 再次 RBAC | 缺失/篡改/撤销凭据：全部六操作 401；角色不足 403 |
| POST `/v1/projects` | A，PROJECT_CREATE | `created_by=principal.subject`；active tenant；ProjectRepository.add 比较 tenant | viewer/operator/auditor 403；body tenant_id 422 |
| GET `/v1/projects` | V/O/A，PROJECT_READ | active tenant；ProjectRepository.list 带 tenant predicate | auditor 403；另一租户看不到列表内容 |
| POST `/v1/runs` | O/A，RUN_CREATE | active tenant；run tenant 与 repository context 一致；项目必须属于租户；幂等键按租户查找 | viewer/auditor 403；外租户项目 404；body tenant_id 422 |
| GET `/v1/runs/{id}` | V/O/A，RUN_READ | active tenant；run_id + tenant_id 查询 | 外租户与缺失 run 404；伪造 X-Tenant-ID/query 无效 |
| POST `/v1/runs/{id}/cancel` | O/A，RUN_CANCEL | active tenant；读取及更新均限定 tenant；只取消非终态 | viewer/auditor 403；外租户与随机不存在 ID 均 409；不更改目标 run |
| GET `/v1/runs/{id}/reports/{format}` | V/O/A，REPORT_READ | active tenant；仅 json/markdown；制品 metadata 由 run_id + tenant_id + format + 未删除条件查询，随后按内部 object_key 读取并校验 SHA-256 | auditor 403；外租户报告与缺失报告 404；不接收客户 object_key |
| 后台 `process_next(context, owner)` | **可信内部调用者**显式传 TenantContext；不通过 HTTP RBAC | 认领查询 tenant；claim 内携带 run；heartbeat/transition 带 tenant、owner、fencing token、lease 条件；制品 key 由 context tenant/run/artifact 生成 | B 不能认领 A；拿 A claim 在 B 仓储 heartbeat/transition 返回 false；中途停用清理报告、run failed |
| 项目 rename/delete、制品 metadata add/get/mark_deleted | 仅仓储内部操作，当前无对应 HTTP 写路由 | 仓储绑定 tenant，写入检查资源归属 | 现有 storage/artifact 负例通过；不等于对外 API 已实现 |
| API key issue/revoke、TenantRepository 管理 | **可信 CLI/系统管理接口**，直接访问数据库；不是用户 HTTP 接口 | issue 验证 tenant active；revoke 按公共 key_id；TenantRepository 不自带 RBAC | CLI/配置/签发/撤销原测试通过；必须由操作系统/部署策略限制管理权限 |
| health、disabled/local 模式 | health 公开；默认 disabled 不注册商业路由；local 双 opt-in 后使用固定 admin | local 不验证外来凭据，必须只用于受控本地开发 | 现有默认拒绝/双 opt-in 测试通过；代码不负责验证监听地址是否 loopback |

后台任务实际上由 `application/service.py:process_next` 和 `storage/run_repository.py` 实现。当前未找到规范原先列出的 `jobs.py`、常驻队列消费者或独立 worker CLI；不能宣称已经验收跨进程调度系统。

底层 `LabApplicationService`/TenantContext/仓储是可信进程内接口，持有 Python 调用能力可以构造 context；冻结 dataclass 不等于认证凭证。HTTP 调用者必须经过 Authorized 服务。FileArtifactStore 是文件存储适配器，不负责判断客户租户；安全依赖前置授权、metadata 来源以及文件系统只允许可信进程访问。

## 4. 负例与现场结果

现有七个测试文件开工基线：**100 passed，exit 0**。新增 `tests/test_a0_authorization.py` 共 56 个展开用例：

| 新覆盖缺口 | 数量 | 最终结果 |
|---|---:|---|
| 六资源操作 × 缺失/篡改/已撤销凭据 | 18 | 401，无资源 ID/凭据回显；run 仍 queued |
| viewer/operator/auditor 所有禁止操作 HTTP 矩阵 | 10 | 403 permission_denied |
| 相同禁止操作绕过 HTTP 调用 Authorized 服务 | 10 | AuthorizationError，底层服务零调用 |
| 已验证身份 × 缺失/停用租户 × 六操作 | 12 | 403 tenant_access_denied，错误结构不含租户信息 |
| API key 的租户不能被 header/query 覆盖 | 1 | 404 run_not_found |
| run body 伪造 tenant_id | 1 | 422 validation_error |
| 权限拒绝时 token 不进入日志（含结构化 extra） | 1 | 日志存在但无 token/secret |
| worker 评估后/制品写入后停用 | 2 | TenantAccessError、run failed、无报告文件/metadata，B run 不变 |
| A claim 经 B 仓储续租/转换 | 1 | 两次 false，A 状态未改变 |

最终八文件联合运行：**156 passed、0 failed、0 skipped，exit 0**。类型引用修正后的逐例证据 [pytest-verified.xml](evidence/a0-20260927/pytest-verified.xml)，控制台 [verified-tests.log](evidence/a0-20260927/verified-tests.log)。此前同轮联合运行的 pytest.xml/final-tests.log 也保留。原 tenant 文件未改；本轮未引用历史测试数作为结论。

新增测试首次为 48 passed、6 failed：测试把 `tenant_a` 当成任意子串检查，误匹配固定错误码 `tenant_access_denied`。实际 403 正确。这是**本轮测试断言缺陷**，已改为校验结构化错误内容与键集合；未修改产品或降低授权要求。失败日志 [negative.log](evidence/a0-20260927/negative.log) 保留。

## 5. 实际命令、环境与检查

解释器：`<python-3.14>\python.exe`，Python 3.14.6。pytest 9.1.1、Ruff 0.16.1、FastAPI 0.139.2、SQLAlchemy 2.0.51、PyJWT 2.13.0、httpx 0.27.2；见 [tool-versions.json](evidence/a0-20260927/tool-versions.json)。mypy 1.20.2 及其开发工具依赖仅安装在新建 TEMP 目录，未修改全局解释器安装、项目清单或生产依赖。工具路径、包版本与安装退出码见 mypy-tools.json/mypy-install.log。

在 Agent 仓执行（两次 pytest 均使用新建独立 basetemp，实际路径在对应 status.json）：

```powershell
$pythonExe = '<python-3.14>\python.exe'
$env:PYTHONPATH = 'src;..\000shared-llm-core\src'
$env:PYTHONIOENCODING = 'utf-8'
$env:LLM_PROVIDER = 'fake'
$a0Base = Join-Path $env:TEMP ('agent-a0-verified-' + [guid]::NewGuid().ToString('N'))
& $pythonExe -m pytest tests/test_auth.py tests/test_tenant_isolation.py tests/test_api_v1.py tests/test_run_repository.py tests/test_storage.py tests/test_artifacts.py tests/test_commercial_e2e.py tests/test_a0_authorization.py -q -o addopts= --basetemp $a0Base --junitxml=docs/evidence/a0-20260927/pytest-verified.xml
& $pythonExe -m ruff check tests/test_a0_authorization.py
# 使用本轮独立工具目录；若已清理，先在新的 TEMP 目录按下面说明恢复工具。
$a0Tools = (Get-Content docs/evidence/a0-20260927/mypy-tools.json -Raw | ConvertFrom-Json).target
$env:PYTHONPATH = "$a0Tools;src;..\000shared-llm-core\src"
$env:MYPYPATH = 'src;..\000shared-llm-core\src'
& $pythonExe -m mypy --strict --follow-imports silent --cache-dir "$a0Tools/cache" tests/test_a0_authorization.py
git diff --check
```

上面的 JUnit 路径是本轮实际路径；再次运行请改成新路径，保留本轮证据。开工基线命令与最终 pytest 相同，但不含新测试文件与 `--junitxml`；初版负例命令仅选新测试文件。安装实际命令为 `& $pythonExe -m pip install --disable-pip-version-check --target $a0TypeTools 'mypy==1.20.2'`，其中 `$a0TypeTools` 是新建的 TEMP/agent-a0-typecheck-GUID 路径。网络仅用于下载开发检查工具，未发送项目源码。类型检查后续 pytest 使用原 PYTHONPATH，不包含临时工具目录。所有测试只用自建 SQLite/制品目录和合成身份；原有 commercial E2E 有真实 loopback health HTTP 测试，未调用客户服务或外部模型。

| 检查 | 实际退出码 | 判断 |
|---|---:|---|
| `python.exe ../scripts/repair_links.py --check` | 0 | 11 个链接 ok；没有复制/改写链接目标 |
| 现有七文件 pytest | 0 | 100 passed |
| 初版新负例 pytest | 1 | 6 个测试断言误判，48 passed；见上节 |
| 最终八文件 pytest | 0 | 156 passed |
| 新测试初版 Ruff | 1 | import 格式，已修正 |
| 新测试最终 Ruff | 0 | All checks passed；没有顺手格式化旧代码 |
| 新测试 mypy | 1 | No module named mypy；**环境失败，未进行类型分析** |
| 独立目录安装 mypy 1.20.2 | 0 | 仅开发检查工具，未改生产依赖 |
| 初次安装后 mypy | 1 | 源码搜索路径未配置，报缺少 py.typed；通过 MYPYPATH 指向本地源码解决 |
| 首次 strict mypy | 1 | 新测试引用模块未显式导出的导入；改从定义模块导入，未改产品 |
| 最终 strict mypy | 0 | 新测试 1 source file 无问题；follow-imports silent，不宣称全产品严格类型检查通过 |
| 类型引用修正后 pytest / Ruff | 0 / 0 | 再次 156 passed / All checks passed |
| `git diff --check` | 0 | 最终差异无空白错误；Git CRLF 提示不是错误 |

本机无 Agent `.venv/Scripts/python.exe`，PATH 起初未找到 mypy/pyright；未因此跳过检查，已按上述方式补齐临时开发工具。使用已获准运行的绝对解释器执行，未通过更改权限解决环境问题。Git 在沙箱读取用户全局 ignore 提示 Permission denied，状态/HEAD 仍成功；未修改全局 Git 配置。寻找旧文档中的 jobs.py/jobs 目录得到不存在，属于文档陈旧，已在 tech-spec 纠正。

## 6. 未验证条件与下一步

1. A0 本机检查已无未解决阻塞；临时开发工具可能被系统清理，复跑时需恢复。没有测试全产品所有代码或宣称干净环境安装已验收。
2. OIDC 只验证本机生成 RSA/JWT 及模拟 Principal；真实 IdP、密钥轮换、时钟偏差策略、网关/反向代理的认证头处理尚未部署验收。
3. PostgreSQL 仅现有配置构造测试，未连接真实数据库。多 API/worker 实例的行锁、租约竞争、事务隔离、停用与提交的真实并发竞态未验收。当前停用检查是几个阶段的检查点，不保证正在执行的任务立即终止，也不证明所有时序下原子停用。
4. 只有真实本机 health HTTP；授权矩阵使用进程内 ASGI。TLS、监听地址、管理 CLI 权限、secret manager、数据库/制品目录 ACL、跨租户进程/文件隔离需要真实部署验证。底层管理接口不能暴露为无授权客户调用。
5. subprocess 约束不是生产隔离。本轮未运行 A2 逃逸/内核沙箱验收，也没有生产执行权限承诺。
6. 未开展 A1、SOC 轨迹桥接、Code、Firmware 工作；未改 FindingSource、冻结接口、技术栈或依赖。未自动提交、推送或部署。

下一项最小任务建议为生产部署前的权限验证计划：固定实际 OIDC 与 PostgreSQL/worker 拓扑，明确自建租户负例和并发停用判定。本轮不执行该部署工作，也不启动 A1/A2；真实多租户验收不能由本轮测试代替。
