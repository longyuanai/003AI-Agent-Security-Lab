"""Registry API for built-in and plugin-provided ATLAS techniques."""

from __future__ import annotations

import warnings
from collections.abc import Iterable
from importlib.metadata import entry_points

from ai_agent_lab.atlas import ATLASTactic

ENTRY_POINT_GROUP = "longyuanai.atlas_tactics"

ATLAS_TACTICS: dict[str, ATLASTactic] = {}


def register_tactics(tactics: Iterable[ATLASTactic]) -> None:
    """Register tactics, rejecting duplicate IDs."""

    for tactic in tactics:
        if tactic.id in ATLAS_TACTICS:
            raise ValueError(f"duplicate ATLAS technique id: {tactic.id}")
        ATLAS_TACTICS[tactic.id] = tactic


def load_plugin_tactics() -> list[str]:
    """Register tactics advertised by other installed distributions.

    Returns the newly registered IDs. This project's own entry points resolve
    to tactics that the built-in imports below already registered, so they are
    skipped rather than raising on the duplicate. A plugin that fails to import
    warns instead of taking the whole registry down with it.
    """

    registered: list[str] = []
    for entry_point in entry_points(group=ENTRY_POINT_GROUP):
        if entry_point.name in ATLAS_TACTICS:
            continue
        try:
            tactic = entry_point.load()
        except Exception as exc:  # noqa: BLE001 - one bad plugin is not fatal
            warnings.warn(
                f"could not load ATLAS tactic plugin {entry_point.name!r}: "
                f"{type(exc).__name__}: {exc}",
                RuntimeWarning,
                stacklevel=2,
            )
            continue
        if not isinstance(tactic, ATLASTactic):
            warnings.warn(
                f"ATLAS entry point {entry_point.name!r} resolved to "
                f"{type(tactic).__name__}, expected ATLASTactic",
                RuntimeWarning,
                stacklevel=2,
            )
            continue
        register_tactics([tactic])
        registered.append(tactic.id)
    return registered


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

# Third-party tactic packs. Built-ins are already in place, so this only adds
# techniques shipped by other installed distributions.
load_plugin_tactics()
