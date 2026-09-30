# R1/R4：令牌寿命与静态公钥启动校验审查

日期：2026-09-30。状态：**审查、缺口复现和具体实现方案完成；产品修复待确认，尚未实施。** 19项真实部署验收全部未执行。本轮没有配置真实IdP、部署或处理客户数据。

## 1. 确认状态、范围和既有修改

本会话未见负责人选择三项A；最新用户要求明确将其视为推荐。工作区9月29日历史文档记载的批准不覆盖9月30日§11～18调整后的600秒产品上限。因此按用户本轮条件，只做审查、复现、方案与回归，**没有修改auth.py/server.py或其他产品源码**。确认本报告的R1/R4即可授权这两项；不需要同时批准30秒任务停止、设施创建、双钥或JWKS。

根HEAD `4235350fbd4d8858fbaac23f380e6cce87688d61`，Agent HEAD `74fbe58da54e5999acefaed3c572c46c831fe86e`。已读取根规则/交接、Agent README/CAPABILITIES、技术规范/TODO、决策§11～18与已有实施记录、认证/启动实现及现有认证用例。工作区包含既有权限、审计、迁移和测试差异，均保护；开工SHA-256、Git状态与文档备份在 [preflight.json](evidence/r1-r4-review-20260930/preflight.json) 及 `before/`。不得用整体Git还原回滚本轮文档。

## 2. 当前代码与可复现结果

源码：[OIDCAuthenticator](../src/ai_agent_lab/auth.py)、[create_server_app](../src/ai_agent_lab/api/server.py)。OIDC解码检查签名、issuer/audience、sub/iat/exp等，leeway默认30秒；没有计算实际签发寿命。公钥在OIDC分支读取一次，但构造器只检查非空和算法名单，不解析PEM和类型。readiness检查数据库SELECT 1与制品目录，没有验签配置健康检查。

复现使用 [test_review_probes.py](evidence/r1-r4-review-20260930/test_review_probes.py)：确定的测试时钟、合成身份、内存RSA私钥/令牌、临时公钥文件及SQLite/ASGI，无网络。32项材料位于docs证据目录，**不加入默认tests/回归集**；断言旨在准确记录当前行为，不把缺口冻结成未来安全要求。修复后必须将相应断言转为拒绝并加入正式测试，不能因这些观察测试绿色而宣布R1/R4完成。

| 样本/操作 | 现场结果 | 对推荐目标的判断 |
|---|---|---|
| iat→exp寿命599/600秒 | 接受 | 正例，但不能证明已有上限 |
| 601秒与7200秒寿命，签名有效且尚未过期 | 接受 | R1缺口已复现 |
| exp晚于当前时间容忍界29秒；刚到30秒界/31秒 | 29秒接受；30/31秒拒绝 | 现有30秒leeway边界已验证；不应将容差计入签发寿命 |
| iat未来29/31秒 | 前者接受、后者拒绝 | 现有时钟容差行为 |
| 缺iat/exp、值为非数字字符串 | 拒绝 | 现有必需字段和部分非法值检查已有效 |
| 数字字符串iat/exp、小数iat、布尔iat | 接受 | 严格时间类型目标尚未实现，存在兼容变化 |
| exp=iat；exp<iat但落在过期容忍期内 | 接受 | 没有正寿命及字段顺序校验 |
| oidc与api_key+oidc：无公钥参数、文件不存在、空文件 | 启动拒绝（ValueError/FileNotFoundError） | 不重复开发已有效路径；错误信息统一与资源清理仍需设计 |
| 两OIDC模式：非空垃圾公钥文件 | 启动成功、ready200、受保护请求500 | R4不可解析配置缺口已复现，无弱认证回落但失败太晚 |
| 两OIDC模式：EC公钥却配置RS256 | 同上 | R4类型/算法不匹配缺口已复现 |
| disabled/local/api_key：配置未使用且不存在的OIDC公钥路径 | 正常启动、ready200 | 不能全模式无条件读取/要求OIDC公钥 |

逐项分类见 [observed-outcomes.json](evidence/r1-r4-review-20260930/observed-outcomes.json)，JUnit见 [pytest-final.xml](evidence/r1-r4-review-20260930/pytest-final.xml)。没有输出token、Authorization或私钥。无效公钥请求500是实际产品配置缺口；没有据此宣称绕过认证成功。

私钥PEM、证书PEM、EC曲线细分、Ed25519/Ed448、非有限值/显式null/列表等时间值，以及极大整数尚未在本轮逐项运行；它们是确认后实现的必要测试，不用当前32项结果替代。

## 3. R1具体实现方案（待确认）

| 项目 | 拟议行为 / 兼容影响 |
|---|---|
| 适用模式 | OIDCAuthenticator直接调用、oidc模式、api_key+oidc的OIDC分支；API-key分支沿用既有key过期/撤销，不将其有效期缩到600秒；disabled/local不涉及JWT |
| 签发TTL | 外部真实测试IdP设置access token TTL=600秒，本项目是验签器，没有IdP发token入口，不能由本轮产品代码宣称已配置实际IdP |
| 产品上限 | 固定600秒作为OIDC接受上限，不提供放宽参数/关闭开关；允许正寿命小于600。不得只查exp是否过期；签名等可信性验证后，计算0<exp-iat≤600，601拒绝 |
| 时间类型 | iat/exp必需，值为非负JSON整数，排除bool、float、字符串、null和容器；如nbf存在，采用同一类型规则且nbf<exp，同时保留现有生效时间校验。拒绝不一致字段；这会拒绝当前被容忍的非规范类型/零负寿命令牌 |
| 时钟容差 | 保留默认30秒（直接构造器现有0～300范围保持兼容）；仅用于iat/nbf生效和exp过期检查，不放宽600秒寿命上限。服务器不新增可放宽TTL的配置 |
| 顺序与异常 | 不从未验签JWT产生可信身份；沿用issuer/audience/算法白名单验证；类型/差值/时间异常统一AuthenticationError→401，不记录claims/token/异常正文。防止库的整数转换掩盖原始JSON类型 |
| 最小源码范围 | auth.py增加时间字段验证/寿命常量，必要时复用经验签claims；server.py只负责模式组合，不创建第二个认证流程、不改变FindingSource/Principal公共契约 |
| 身份失效边界 | IdP停止旧权限新签发/刷新后，最坏600+30+实际时钟偏差δ秒；未证明真实IdP同步或即时撤销。租户/在途任务停止语义不属于R1 |

确认后的正式测试必须覆盖599/600/601、很长寿命、0/负寿命、缺失/显式null/非法类型/NaN/Infinity/大整数、iat/exp/nbf边界、过期和未来时间、错误签名/issuer/audience、支持模式的各分支；使用确定时钟及真实合成签名。API key较长有效期仍可认证且撤销仍拒绝；local双opt-in、disabled商业路由关闭保持原行为。

## 4. R4具体实现方案（待确认）

只对oidc和api_key+oidc校验配置；无效OIDC配置使组合模式整体启动失败，不能绕过它只提供api_key，也不能回落local/disabled。disabled/local/api_key不检查未使用公钥路径。

在OIDCAuthenticator构造时用**现有cryptography/PyJWT依赖**解析单PEM public key；不接受私钥PEM、对称secret、垃圾文件或误当公钥的证书PEM。明确支持格式为既有公钥PEM（SubjectPublicKeyInfo，RSA格式兼容情况需测试锁定），不新增证书转换/JWKS。保留签名验证所需的解析结果，避免每请求才首次发现配置错误。

| 已支持算法 | 启动时拟议类型/参数校验 |
|---|---|
| RS256/RS384/RS512 | RSA public key，推荐最低2048位；算法列表可多RS项，禁止混入其他家族 |
| ES256 | EC public key，P-256（SECP256R1） |
| ES384 | EC public key，P-384（SECP384R1） |
| ES512 | EC public key，P-521（SECP521R1） |
| EdDSA | Ed25519/Ed448 public key，按当前PyJWT实际支持逐项验证 |

算法白名单保留，但**每个配置算法都要能与这一个公钥匹配**，不能只检查“至少一个可用”。RSA最低位数及严格曲线匹配可能拒绝既有宽松配置，必须在确认中包含兼容影响。

server.py中将这项纯配置预检前置到创建engine/schema/artifact目录之前，失败返回脱敏的统一配置异常，不打印PEM、环境变量或私钥；已经成立的缺参数/不存在文件拒绝仍保留。权限/读文件异常归类为配置/环境失败，不能算没有认证问题。若移动构造顺序涉及其他既有代码，采用最小差异并明确dispose责任，不重构工厂。

静态公钥通过启动解析后不提供热刷新；readiness不声称检查IdP在线或实际令牌成功。正确公钥但不匹配IdP签名key，仍由受控新token正例与OIDC-04验证；不能为了ready通过关闭验签。

正式测试补充：缺配置、缺文件、权限拒绝、空/垃圾/私钥/证书/错误类型/错误曲线/算法混用/弱RSA、各受支持算法正例、重启新旧key四格、非OIDC三模式未使用路径、组合模式不得部分启动、失败不输出敏感材料、不留下新schema/目录。合成私钥只留内存，必要的私钥PEM误配置用内存构造/受控读文件替身测试，不写入证据包。

## 5. 本轮实际验证与失败归类

解释器固定 `<python-3.14>\python.exe`，Agent仓执行；实际独立basetemp见 [final-test-status.json](evidence/r1-r4-review-20260930/final-test-status.json)。PYTHONPATH=`src;..\000shared-llm-core\src;..\000shared-integration\src;.`。本轮未安装生产依赖或修改全局环境；旧TEMP mypy入口缺失，固定1.20.2仅在新TEMP目录恢复为开发检查工具（缓存包），路径和安装退出码见mypy-tools.json。

```powershell
$pythonExe = '<python-3.14>\python.exe'
$env:PYTHONPATH = 'src;..\000shared-llm-core\src;..\000shared-integration\src;.'
$reviewBase = '$env:TEMP\agent-r1r4-review-final-33b303319f1944c7a7e56aeedd02a97e'
& $pythonExe -m pytest docs/evidence/r1-r4-review-20260930/test_review_probes.py tests/test_auth.py tests/test_tenant_isolation.py tests/test_a0_authorization.py tests/test_audit_attribution.py tests/test_api_v1.py -q --tb=short -o addopts= -o junit_family=legacy --basetemp $reviewBase --junitxml docs/evidence/r1-r4-review-20260930/pytest-final.xml
$typeTools = (Get-Content docs/evidence/r1-r4-review-20260930/mypy-tools.json | ConvertFrom-Json).target
$env:PYTHONPATH = "$typeTools;src;..\000shared-llm-core\src;."
$env:MYPYPATH = 'src;..\000shared-llm-core\src;.'
& $pythonExe -m mypy --strict --follow-imports silent --cache-dir "$typeTools\cache" docs/evidence/r1-r4-review-20260930/test_review_probes.py
& $pythonExe -m ruff check docs/evidence/r1-r4-review-20260930/test_review_probes.py
git diff --check
```

| 检查 | 实际结果 | 解释 |
|---|---|---|
| 首次联合pytest | 19 failed / 130 passed，exit1 | 复现材料将datetime改成Mock后再encode，破坏了库的isinstance；这是测试自身错误，已将测试时钟注入移到签名后，未改产品 |
| 修正后的联合pytest | 149 passed / 0 failed / 0 skipped，exit0 | 32观察用例+117原有认证/跨租户/审计/API回归；**不是R1/R4修复通过** |
| 首次mypy / 恢复后 | exit1 / exit0，检查新增复现材料1文件 | 旧TEMP入口缺失属环境失败，恢复后strict通过；没有用历史类型数字替代 |
| 首次Ruff / 最终 | exit1 / exit0 | 新材料Callable导入位置，按规则修正，无忽略规则 |
| 文档引用、源码完整性、git diff --check | 最终结果见integrity.json | 收尾检查只允许技术规范/TODO及本轮新增审查/证据变化 |

后续重跑请新建basetemp和证据输出路径，不覆盖本轮日志。测试私钥/令牌仅内存；只有公开key写pytest临时目录，不进入Git或证据目录。工具与测试TEMP不保证长期保留，应重新核对存在性。

## 6. 确认请求与下一任务

请确认是否按§3/§4实施：OIDC分支严格整数时间、0<exp-iat≤600秒，保留30秒时钟容差；单公钥启动解析、类型/算法逐项匹配和脱敏fail-closed；非OIDC与API-key有效期保持原行为。确认仅授权R1/R4源码修复和正式回归，不授权IdP/PG创建或部署。

公钥切换仍只记录待确认的15分钟维护预算、停流、全部实例重启，在线双钥并存为0；失陷旧钥不得回滚。没有实现双钥/JWKS。30秒租户授权停止和运行中任务停止仍是独立R3/G5/A2任务，本轮没有改变或证明这些行为。真实OIDC-01/03/04/06与其余19项部署验收全部继续未执行。
