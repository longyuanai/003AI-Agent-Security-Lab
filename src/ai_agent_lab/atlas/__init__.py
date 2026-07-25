"""Safe MITRE ATLAS tactic templates for lab-only simulations."""

from __future__ import annotations

from dataclasses import dataclass

from shared_llm_core import FindingSeverity


@dataclass(frozen=True)
class ATLASTactic:
    """One immutable ATLAS technique with synthetic payload variants."""

    id: str
    name: str
    description: str
    payloads: tuple[str, ...]
    severity_default: FindingSeverity
    mitre_url: str

    def __post_init__(self) -> None:
        if not self.id.startswith("AML.T"):
            raise ValueError(f"invalid ATLAS technique id: {self.id!r}")
        if len(self.payloads) < 5:
            raise ValueError(
                f"{self.id} must provide at least five safe payload variants"
            )
        if len(set(self.payloads)) != len(self.payloads):
            raise ValueError(f"{self.id} payload variants must be unique")
        if not self.mitre_url.startswith(
            "https://atlas.mitre.org/techniques/"
        ):
            raise ValueError(f"invalid MITRE ATLAS URL: {self.mitre_url!r}")


from ai_agent_lab.atlas.registry import (  # noqa: E402
    ATLAS_TACTICS,
    get_tactic,
    list_tactics,
    register_tactics,
)

__all__ = [
    "ATLASTactic",
    "ATLAS_TACTICS",
    "get_tactic",
    "list_tactics",
    "register_tactics",
]
