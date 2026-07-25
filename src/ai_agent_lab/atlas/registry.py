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
