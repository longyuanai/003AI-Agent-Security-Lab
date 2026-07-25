"""Registry API for built-in and plugin-provided ATLAS techniques."""

from __future__ import annotations

from collections.abc import Iterable

from ai_agent_lab.atlas import ATLASTactic


ATLAS_TACTICS: dict[str, ATLASTactic] = {}


def register_tactics(tactics: Iterable[ATLASTactic]) -> None:
    """Register tactics, rejecting duplicate IDs."""

    for tactic in tactics:
        if tactic.id in ATLAS_TACTICS:
            raise ValueError(f"duplicate ATLAS technique id: {tactic.id}")
        ATLAS_TACTICS[tactic.id] = tactic


def get_tactic(tactic_id: str) -> ATLASTactic:
    """Resolve one tactic by case-insensitive ATLAS ID."""

    normalized = tactic_id.strip().upper()
    try:
        return ATLAS_TACTICS[normalized]
    except KeyError as exc:
        raise KeyError(f"Unknown ATLAS tactic: {tactic_id!r}") from exc


def list_tactics() -> list[ATLASTactic]:
    """Return all registered tactics in stable ID order."""

    return [ATLAS_TACTICS[tactic_id] for tactic_id in sorted(ATLAS_TACTICS)]


from ai_agent_lab.atlas.aml_t0020 import TACTICS as AML_T0020_TACTICS  # noqa: E402
from ai_agent_lab.atlas.aml_t0024 import TACTICS as AML_T0024_TACTICS  # noqa: E402
from ai_agent_lab.atlas.aml_t0031 import TACTICS as AML_T0031_TACTICS  # noqa: E402
from ai_agent_lab.atlas.aml_t0040 import TACTICS as AML_T0040_TACTICS  # noqa: E402
from ai_agent_lab.atlas.aml_t0048 import TACTICS as AML_T0048_TACTICS  # noqa: E402
from ai_agent_lab.atlas.aml_t0050 import TACTICS as AML_T0050_TACTICS  # noqa: E402
from ai_agent_lab.atlas.aml_t0051 import TACTICS as AML_T0051_TACTICS  # noqa: E402
from ai_agent_lab.atlas.aml_t0054 import TACTICS as AML_T0054_TACTICS  # noqa: E402


for _builtin_tactics in (
    AML_T0020_TACTICS,
    AML_T0024_TACTICS,
    AML_T0031_TACTICS,
    AML_T0040_TACTICS,
    AML_T0048_TACTICS,
    AML_T0050_TACTICS,
    AML_T0051_TACTICS,
    AML_T0054_TACTICS,
):
    register_tactics(_builtin_tactics)
