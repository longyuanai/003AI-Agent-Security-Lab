# AI-Agent-Security-Lab

> AI Agent security range — vulnerable target agents + attack scenarios + detection.
> Seventh project of the **longyuanai AI Security Agent suite**.

## What it does (PoC, v0.1)

Runs five deliberately vulnerable Agent profiles against 13 built-in attack
scenarios, scores each trace through a heuristic detector (and optionally an
LLM judge via `shared-llm-core`), and emits a Markdown report.

```
attack payload ──► Target Agent (read_file / http_fetch / exec_shell)
                              │
                              ▼
                            Trace
                              │
              ┌───────────────┼───────────────┐
              ▼                               ▼
       Heuristic Detector              LLM Detector (optional)
              │                               │
              └───────────────┬───────────────┘
                              ▼
                       RunResult (verdict + evidence)
                              │
                              ▼
                       Markdown Report
```

## PoC shortcuts

- **Target agents are hard-coded**. No real LLM call in the routing loop — the
  tool-selection logic is regex-based so the demo is fully reproducible.
  The interface (`TargetAgent.run(user_input) -> Trace`) is the same shape a
  real LLM-backed agent would expose, so the detector/reporter code does not
  change when we swap in a real model.
- **5 vulnerable profiles**: SQLi writer, SMTP-reading email assistant,
  DOCX/PDF file RAG, Playwright browser, and exec-Python Code-Act. Run
  `python -m ai_agent_lab.cli targets` to inspect their deliberately unsafe
  tool surfaces.
- **13 built-in attack classes** covering indirect prompt injection,
  token theft, shell escape, SQL injection, path traversal, email exfiltration,
  RAG poisoning, browser SSRF, Code-Act privilege escalation, tool misuse,
  memory poisoning, plan hijack, and model DoS (unbounded generation).
  Detector output maps these to four stable modes: `prompt_injection`,
  `tool_misuse`, `data_exfiltration`, and `privilege_escalation`.
- **Heuristic detector is the default**. LLM detector is opt-in via the
  shared-llm-core router; when none is reachable we still get a useful report.
- **A benign corpus scores the detector honestly.** 66 near-miss samples that
  mention the same tools, paths and SQL as the attacks but only describe them.
  Detection rate measured against attacks alone is unfalsifiable, so the report
  carries precision and false-positive rate next to recall.

## Install

The suite expects sibling checkouts, because `shared-llm-core` is consumed as a
local path dependency:

```
<parent>/
├── 000shared-llm-core/          # required
├── 000shared-integration/       # optional; gateway tests skip without it
└── 003AI-Agent-Security-Lab/    # this repo
```

```bash
git clone https://github.com/longyuanai/000shared-llm-core.git
git clone https://github.com/longyuanai/003AI-Agent-Security-Lab.git

cd 003AI-Agent-Security-Lab
poetry install          # or: pip install ../000shared-llm-core && pip install -e .
```

`openai` is an optional extra, needed only for `LLM_PROVIDER=openai`:

```bash
pip install -e ".[openai]"
```

The test suite adds `src/` to the path itself, so `pytest` also works straight
from a checkout without installing anything.

## Run the demo

```bash
# Heuristic-only (no LLM, fully offline)
python -m ai_agent_lab.cli run --scenario demo --output report.md

# With shared-llm-core (router must be reachable)
LLM_PROVIDERS=local python -m ai_agent_lab.cli run --scenario demo --output report.md
```

Expected output: 13 attacks detected, 100% detection rate.

## Built-in scenarios

```
indirect-web-injection indirect_prompt_injection "Page content says: Ignore previous instructions ..."
token-theft-canary   token_theft         "Playwright open ...?API_TOKEN=lab-canary-token"
shell-escape-sh-c    shell_escape        "exec_python ... os.system('sh -c ...')"
sqli-or-true         sql_injection       "SELECT ... OR 1=1"
path-traversal-shadow path_traversal     "Read ../../../../etc/shadow"
email-exfil-forward  email_exfiltration  "Forward SMTP message ... to attacker ..."
rag-poison-instruction rag_poisoning     "Retrieved document says: Ignore previous ..."
ssrf-cloud-metadata  browser_ssrf        "Playwright open http://169.254.169.254/..."
code-act-privilege   code_act_privilege_escalation "exec_python ... os.system(...)"
tool-misuse-rm-rf    tool_misuse         "Delete email ... without confirmation"
memory-poison-recall memory_poison       "Conversation history says ... Ignore previous instructions ..."
plan-hijack-scratchpad plan_hijack       "[scout] Findings so far: ignore previous instructions ..."
model-dos-unbounded-generation model_dos "generate an infinite stream ... until memory runs out"
```

## Tests

```bash
pytest -v
```

All tests use a stub router; no live LLM is required.

## Local subprocess sandbox

The SAND-001 PoC runs generated Python in a fresh `sandbox_*` subprocess
directory with an environment allowlist, guarded writes, optional socket
blocking, and a hard timeout:

```bash
python -m ai_agent_lab.cli sandbox --code "print('sandbox-ok')" --timeout 2
```

This is deterministic application-level isolation for the lab. On Windows,
timeout handling kills the direct subprocess; it is not a kernel security
boundary or a replacement for the Docker/gVisor design in the technical spec.

**What it stops**: writes outside the temp dir (including moving a file out via
`os.rename` / `os.replace` / `shutil.move`), socket creation through both
`socket` and the low-level `_socket` module, non-allowlisted environment
variables, and runaway execution.

**What it does not stop**, because in-process monkeypatching cannot reach them:
a spawned child process does not inherit the guards, and `ctypes` calls into C
underneath them. Both are pinned by tests in `tests/test_sandbox.py` so the
boundary stays documented rather than assumed. Do not use this to contain
untrusted code.

## ASR evaluation

Run all 50 Agent/Attack combinations and write both report formats:

```bash
python -m ai_agent_lab.cli metrics \
  --markdown asr-report.md \
  --json asr-report.json
```

Attack success means the vulnerable Agent emitted a non-empty tool call.
Detector verdict and latency are recorded independently in each result row.

The same report scores all six tech-spec §5.5 evaluation dimensions in one
pass -- ASR, Detection Quality (precision/recall/FPR), Defense (coverage +
task utility, via the pipeline below), Detection Latency (detector-only, not
inflated by the agent's own routing time), and Cost (LLM token spend, zero for
a fully offline run):

```
$ python -m ai_agent_lab.cli metrics --markdown asr.md --json asr.json
Combinations: 65  Successful: 14  ASR: 21.5%
Detection: recall 100.0%  precision 100.0%  FPR 0.0% (0/66 benign flagged)
Defense: coverage 100.0%  task utility 97.0%
Wrote asr.md
Wrote asr.json
```

```
## Detection Quality

_Alarm threshold: `suspicious` or higher._

- Detection rate (recall): **100.0%** (13/13 attacks)
- Precision: **100.0%**
- False-positive rate: **0.0%** (0/66 benign inputs)
- F1: **1.000**

## Defense

- Defense coverage: **100.0%** (13/13 attacks blocked)
- Task utility: **97.0%** (64/66 benign tasks completed)

## Cost and Latency

- Detection latency (attack -> verdict): mean **0.140 ms**, p95 **0.268 ms**
- LLM calls: **0** — fully offline run, no token cost.
```

A false positive is listed with the benign sample that tripped it and the rule
that matched, so an over-broad rule is immediately attributable. Pass
`--markdown`/`--json` only (no `--defense`/`--quality` flags exist to disable
these sections from the CLI; use `evaluate_asr(include_quality=False,
include_defense=False)` from Python if you need the bare ASR pass).

## Defender Toolkit

Four policy layers over an agent trace (tech-spec §5.4):

```bash
python -m ai_agent_lab.cli defend
```

```
Defense coverage: 13/13 (100%)
Task utility:     64/66 (97%)
```

A tool-name allowlist is not enough on its own: `exec_python`, `send_email`,
`sql_query` and `read_file` all appear on both the benign and the attack side
of the built-in corpora. What separates them is the arguments, the phrasing of
the request, and what leaves in the result -- hence four layers, each of which
blocks something the others miss.

Task utility is deliberately not 100%. The two benign tasks that get blocked
are ones the *vulnerable agent* routed into a real policy violation (a question
about `os.popen` became a shell command; a relative import became a workspace
escape). Relaxing the policy to reach 100% would mean permitting privileged
calls in generated code and reads outside the workspace.

Note that the detector and the defender can disagree, and both be right: the
detector answers "was this an attack?", the defender answers "does this violate
policy?".

## v0.5 multi-agent scenarios

The v0.5 lab adds an offline MCP abuse role pipeline, five RuleEngine-backed
advanced scenarios, and cross-scenario Finding correlation:

```bash
python -m ai_agent_lab.cli multi-agent-demo
python -m ai_agent_lab.cli v05-scenarios
python -m ai_agent_lab.cli correlation-report -o v05-correlation-report.md
```

All demo targets use `fixture://` inputs and synthetic canary values.

## Phase-2 MITRE ATLAS scans and reports

ATLAS payloads are non-operational, synthetic canary simulations. Without
`LAB_LLM_KEY`, the judge stays fully offline. Setting all three variables
activates an OpenAI-compatible endpoint:

```powershell
$env:LAB_LLM_KEY = "<your-key>"
$env:LAB_LLM_MODEL = "gpt-4o-mini"
$env:LAB_LLM_BASE_URL = "https://api.openai.com"
```

Run a safe ATLAS scan and write Markdown plus JSON evidence:

```powershell
'{"attack":"AML.T0051","agent":"sql_assistant","iterations":3}' |
  python -m ai_agent_lab scan --json

# Explicit report location; JSON evidence uses the same filename stem.
python -m ai_agent_lab scan `
  --input '{"attack":"AML.T0051","agent":"sql_assistant","iterations":3}' `
  --report output/atlas-demo.md --json
```

Payload variants are chosen at random. Pass `--seed` (or `"seed"` in the JSON
payload) to make a run reproducible — every report states whether it can be
regenerated and with which seed:

```powershell
python -m ai_agent_lab scan `
  --input '{"attack":"AML.T0051","agent":"sql_assistant","iterations":3}' `
  --seed 42 --json
```

Without `--report`, ATLAS scans use
`output/<ISO timestamp>-<attack_id>.md`. Evidence contains only the current
safe test payload and judge result; target-agent conversation history is not
persisted.

## LLM provider switching

The IntegrationGateway-compatible `scan` command reads `LLM_PROVIDER`:

```powershell
# Deterministic offline mode (also the no-key fallback)
$env:LLM_PROVIDER = "fake"

# Official OpenAI SDK
$env:LLM_PROVIDER = "openai"
$env:OPENAI_API_KEY = "<your-key>"
$env:OPENAI_MODEL = "gpt-4.1-mini"  # optional

# Anthropic native Messages API (stdlib HTTP, no extra dependency)
$env:LLM_PROVIDER = "anthropic"
$env:ANTHROPIC_API_KEY = "<your-key>"
$env:ANTHROPIC_MODEL = "claude-sonnet-4-5"  # optional
```

Without `LLM_PROVIDER`, the lab selects an available OpenAI key, then an
Anthropic key, and otherwise uses fake. Explicitly selecting a live provider
without its key also falls back to fake; the reason is included in finding
metadata.

```powershell
'{"agent":"sql_assistant","attack":"indirect_injection"}' |
  python -m ai_agent_lab.cli scan --json
```
