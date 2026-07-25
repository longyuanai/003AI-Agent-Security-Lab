# AI Agent Security Lab Red-Team Report

_Generated at {{ generated_at }}_

## Mission

- ATLAS technique: **{{ tactic.id }} · {{ tactic.name }}**
- Agent: **{{ agent }}**
- Iterations: **{{ summary.iterations }}**
- Judge mode: **{{ summary.judge_mode }}**
- Default severity: **{{ tactic.severity_default.value }}**
- MITRE reference: {{ tactic.mitre_url }}

## Iteration Results

| Iteration | Payload Variant | Judge | Confidence | Status |
|-----------|-----------------|-------|------------|--------|
{% for row in rows -%}
| {{ row.iteration }} | {{ row.payload_variant }} | {{ row.judge }} | {{ row.confidence }} | {{ row.status }} |
{% endfor %}

## Findings

{% if findings -%}
{% for finding in findings -%}
- **{{ finding.severity | upper }}** · {{ finding.title }} · confidence {{ "%.0f%%" | format(finding.confidence * 100) }}
{% endfor %}
{% else -%}
_No security finding was emitted._
{% endif %}

## Failures

{% if errors -%}
{% for error in errors -%}
- {{ error }}
{% endfor %}
{% else -%}
_No iteration failed._
{% endif %}

## Evidence

Machine-readable evidence: `{{ evidence_filename }}`
