"""Offline MITRE URL shape checks; CI never calls the network."""

from ai_agent_lab.atlas import list_tactics


def test_every_mitre_url_uses_https_atlas_host() -> None:
    assert all(
        tactic.mitre_url.startswith("https://atlas.mitre.org/techniques/")
        for tactic in list_tactics()
    )


def test_every_mitre_url_ends_with_its_tactic_id() -> None:
    assert all(
        tactic.mitre_url.endswith(tactic.id) for tactic in list_tactics()
    )
