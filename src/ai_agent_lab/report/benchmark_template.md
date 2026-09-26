# AI Agent Security Benchmark Report

## Run Manifest

- Run ID: `{{ run_id }}`
- Evidence schema: `{{ schema_version }}`
- Generated: {{ generated_at }}
- Seed: {{ seed }}
- Lab version: {{ lab_version }}
- Benchmark fingerprint: `{{ benchmark_fingerprint }}`
- Suite manifest: `{{ manifests.suite_sha256 }}`
- ATLAS registry: `{{ manifests.registry_sha256 }}`
- Success rule: `{{ manifests.success_oracle }}`
- Detector rule: `{{ manifests.detector }}`

## Executive Summary

| Runs | Attacks | ASR | Benign controls | Utility | False refusal |
|------|---------|-----|-----------------|---------|---------------|
| {{ summary.total }} | {{ summary.attack_total }} | {{ "%.1f%%" | format(summary.asr * 100) }} | {{ summary.benign_total }} | {{ "%.1f%%" | format(summary.utility_rate * 100) }} | {{ "%.1f%%" | format(summary.false_refusal_rate * 100) }} |

## Detector and Judge Quality

| Signal | Result |
|--------|--------|
| Detector true-positive rate | {{ "%.1f%%" | format(summary.detector.tpr * 100) }} |
| Detector false-negative rate | {{ "%.1f%%" | format(summary.detector.fnr * 100) }} |
| Detector false-positive rate | {{ "%.1f%%" | format(summary.detector.fpr * 100) }} |
| Judge/objective agreement | {{ "%.1f%%" | format(summary.judge.agreement * 100) }} |

Attack Success is determined by the objective state-effect Oracle. Detector and Judge results are independent signals.

## Results by Agent

| Agent | Runs | ASR | Utility |
|-------|------|-----|---------|
{% for name, row in by_agent.items() %}| {{ name }} | {{ row.total }} | {{ "%.1f%%" | format(row.asr * 100) }} | {{ "%.1f%%" | format(row.utility_rate * 100) }} |
{% endfor %}

## Results by Attack

| Attack | Attempts | Successes | ASR |
|--------|----------|-----------|-----|
{% for name, row in by_attack.items() %}| {{ name }} | {{ row.attack_total }} | {{ row.attack_successes }} | {{ "%.1f%%" | format(row.asr * 100) }} |
{% endfor %}

## Results by Delivery Strategy

| Strategy | Runs | Attacks | ASR | Utility |
|----------|------|---------|-----|---------|
{% for name, row in by_strategy.items() %}| {{ name }} | {{ row.total }} | {{ row.attack_total }} | {{ "%.1f%%" | format(row.asr * 100) }} | {{ "%.1f%%" | format(row.utility_rate * 100) }} |
{% endfor %}

## Objective Evidence

| Task | Agent | Kind | Tool | Objective | Boundary | Detector | Judge |
|------|-------|------|------|-----------|----------|----------|-------|
{% for row in records %}| {{ row.task_id }} | {{ row.agent }} | {{ row.kind }} | {{ row.tool }} | {{ "success" if row.attack_success else ("control-complete" if row.task_completed else "not-observed") }} | {{ row.state_effect.boundary if row.state_effect else "-" }} | {{ row.detector_verdict }} | {{ row.judge_verdict }} |
{% endfor %}

## Privacy and Limitations

- Evidence policy: `{{ privacy.content_policy }}`.
- Input content persisted: **{{ privacy.input_content_persisted }}**.
- Model content persisted: **{{ privacy.model_content_persisted }}**.
- Agent history persisted: **{{ privacy.agent_history_persisted }}**.
- Input digests prove fixture identity but are not treated as anonymization.
- This automated benchmark complements, and does not replace, authorized human security review.
