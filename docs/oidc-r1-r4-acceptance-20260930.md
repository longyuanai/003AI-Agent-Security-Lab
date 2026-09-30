# R1/R4 本机修复验收 — 2026-09-30

状态：负责人本轮明确确认按[审查报告§3/§4](oidc-r1-r4-review-20260930.md)实施；源码最小修复与本机L1验收完成。**19项真实部署验收全部未执行**，没有配置真实IdP、连接生产数据库或部署。三项A的其他调整不因此转为批准。

## 1. 工作区保护与范围

根HEAD `4235350fbd4d8858fbaac23f380e6cce87688d61`，Agent HEAD `74fbe58da54e5999acefaed3c572c46c831fe86e`，均未改变。开工前已有大量未提交源码/文档/测试；完整状态、SHA256和明确授权记录见 [preflight.json](evidence/r1-r4-fix-20260930/preflight.json)。本轮改动前将auth.py、server.py、tech-spec.md、TODO.md原字节保存在证据目录before/；恢复须仅撤回本轮差异，不能用Git HEAD覆盖已有工作。

本轮仅改 `src/ai_agent_lab/auth.py`、`src/ai_agent_lab/api/server.py`，新增 `tests/test_oidc_limits_and_keys.py`，更新技术规范/TODO并新增本报告与证据。原有认证授权、服务、存储、审计及tenant测试保护结果见 [integrity.json](evidence/r1-r4-fix-20260930/integrity.json)。未修改其他产品、依赖清单、FindingSource或公共契约。类型标注补齐工厂返回/认证器协议和已校验Role集合，未改变API-key行为。

## 2. 行为与兼容影响

| 项目 | 修复后行为与现场证据 |
|---|---|
| 时间字段 | 验签及issuer/audience检查后检查原始JSON类型；iat/exp必需非负整数，排除bool/float/字符串/null/容器/非有限值；nbf可选但同类型且nbf<exp。缺字段、非法值与巨大时间统一认证拒绝 |
| 实际寿命 | 固定 `0 < exp-iat <= 600`，599/600接受，601/7200拒绝，零/负寿命拒绝；容差不参与寿命计算 |
| 时钟容差 | 默认30秒；过期29秒接受，30/31秒拒绝；iat未来29秒接受、31秒拒绝；nbf验证及顺序断言通过。直接构造器既有0～300秒范围保留；无放宽寿命开关 |
| 静态公钥 | 启动解析public PEM并保存解析结果，逐项校验算法；RS256/384/512要求RSA≥2048，ES256/384/512分别要求P-256/P-384/P-521，EdDSA接受Ed25519/Ed448。两OIDC模式各算法实际合成签名、受保护请求200/无凭据401与ready200通过 |
| 错误配置 | 缺配置、缺文件、空/垃圾、EC配RS256、曲线错配、算法家族混用、弱RSA、DSA、对称材料、私钥、证书、权限拒绝均启动失败，DB/schema及制品目录尚未创建。读取/解析错误脱敏，无local/API-key弱认证回落 |
| 兼容 | disabled/local/api_key忽略未使用公钥路径，原测试正常。组合模式30天API key仍可认证，撤销后401；超长JWT返回401。RSA PKCS1公钥及单RSA多RS算法配置通过 |
| 切换 | 沿用维护停流、全部实例重启；现有本地切换回归通过，不代表真实实例切换已执行。未新增双钥/JWKS或热刷新 |

这是收紧接受策略：旧超长、非规范时间、弱密钥与算法/曲线错配配置将被拒绝，部署前需检查IdP输出及公钥配置。项目是令牌验证器，没有外部IdP签发入口；实际签发TTL=600秒仍需在真实测试IdP设置并验收。角色降权后的令牌失效上界仍依赖IdP不再签发/刷新旧角色及真实时钟偏差，不提供即时撤销。

## 3. 本轮实际验证

解释器绝对路径 `<python-3.14>\python.exe`，Python3.14.6、PyJWT2.13.0、cryptography50.0.0、pytest9.1.1、mypy1.20.2、Ruff0.16.1。版本见 [runtime-versions.json](evidence/r1-r4-fix-20260930/runtime-versions.json)。mypy仅缓存恢复到独立TEMP开发工具目录，安装exit0；未增加生产依赖。以下命令在Agent目录实际运行，最终独立basetemp原路径见 [pytest-final-status.json](evidence/r1-r4-fix-20260930/pytest-final-status.json)，重跑请使用新GUID。

```powershell
$pythonExe = '<python-3.14>\python.exe'
$env:PYTHONPATH = 'src;..\000shared-llm-core\src;..\000shared-integration\src;.'
$testBase = Join-Path $env:TEMP ('agent-r1r4-final-' + [guid]::NewGuid().ToString('N'))
& $pythonExe -m pytest tests/test_oidc_limits_and_keys.py tests/test_auth.py tests/test_tenant_isolation.py tests/test_a0_authorization.py tests/test_audit_attribution.py tests/test_api_v1.py tests/test_deployment_authorization_materials.py tests/test_commercial_e2e.py tests/test_run_repository.py --basetemp $testBase -o addopts= -o junit_family=legacy --tb=short --junitxml docs/evidence/r1-r4-fix-20260930/pytest-final.xml
$typeTools = (Get-Content docs/evidence/r1-r4-fix-20260930/mypy-tools.json | ConvertFrom-Json).target
$env:PYTHONPATH = "$typeTools;src;..\000shared-llm-core\src;..\000shared-integration\src;."
$env:MYPYPATH = 'src;..\000shared-llm-core\src;..\000shared-integration\src'
& $pythonExe -m mypy --strict --follow-imports silent src/ai_agent_lab/auth.py src/ai_agent_lab/api/server.py tests/test_oidc_limits_and_keys.py
& $pythonExe -m ruff check src/ai_agent_lab/auth.py src/ai_agent_lab/api/server.py tests/test_oidc_limits_and_keys.py
git diff --check
```

| 检查 | 实际结果与证据 |
|---|---|
| 修复前静态基线 | mypy exit1，原有4条类型错误；Ruff exit1，原有3条导入/未使用导入问题；日志保留于mypy-before.log/ruff-before.log |
| 首轮修复回归 | 248 passed，exit0，pytest-first.log/xml；后补对称材料/不支持DSA两个负例 |
| 新增检查首次Lint | Ruff exit1，新helper异常风格问题；按规则改写，无忽略规则，ruff-fix.log保留；mypy-first exit0 |
| 最终回归 | **250 passed / 0 failed / 0 skipped，exit0**，其中新文件95项、原有回归155项；[最终JUnit](evidence/r1-r4-fix-20260930/pytest-final.xml)、[日志](evidence/r1-r4-fix-20260930/pytest-final.log) |
| 最终严格mypy / Ruff | 3个涉及文件均通过，分别exit0；[状态](evidence/r1-r4-fix-20260930/static-final-status.json)与同目录final日志 |
| 目录链接 / 文档引用 / 保护摘要 / diff检查 | links-check.log与integrity.json保存实际结果；包含新文件空白检查，不以历史记录替代 |

旧docs/evidence下观察断言保持实施前档案；正式测试已将宽松接受与ready后500观察转换为拒绝/启动失败断言。所有签名令牌和私钥仅内存，测试只在独立pytest目录写公开PEM；私钥/证书误配置使用受控内存读替身，不输出完整令牌、私钥或客户数据。受影响源码和证据敏感材料检查结果见integrity.json。

Git全局ignore文件读取权限与LF/CRLF提示属于环境提示，未修改全局配置；公钥PermissionError用合成替身验证，不声称实际部署文件ACL已测。此轮未发生pytest产品失败；修复前缺口已由历史复现锁定，历史通过数字不计入本轮结论。

收尾核验：297个既有文件摘要未变，仅4个允许文件发生变化，4份before备份与开工摘要一致；25个本地引用有效、根仓干净且HEAD未变。`git diff --check` exit0；新文件 `git diff --no-index --check NUL <file>` 返回1表示新增差异，两份检查日志均无空白错误，手工行尾检查也通过。导出本轮delta同样返回1，不是产品失败；最终汇总检查exit0，见 [final-check-status.json](evidence/r1-r4-fix-20260930/final-check-status.json)。

## 4. 未验证与下一项

真实OIDC签发/撤销/映射、受控停流与全实例重启、专用PostgreSQL备份恢复及多实例任务领取、网络日志和实际ACL均未执行；设施不假定存在。[部署权限计划](deployment-authorization-validation-plan.md)19项保持not_run，以上仅本机合成数据L1证据，不代表SaaS多租户或生产隔离验收。

下一项可执行任务：独立审查R3/G5租户授权停止30秒目标，明确触发点、任务检查点、取消/重启/制品处置语义后形成最小修复范围。运行中任务停止及A2生产执行隔离本轮未实现。真实部署执行需要另外明确授权与测试IdP、专用PG、多实例、测试账号及清理/恢复负责人；本轮未部署、提交或推送。
