"""Web3 transaction replay scenario."""

from __future__ import annotations

from ai_agent_lab.v05_compat import (
    Finding,
    FindingSeverity,
    FindingSource,
    Rule,
    RuleContext,
    RuleRegistry,
    new_finding_id,
)


RULE_ID = "003-web3-transaction-replay"


class Web3ReplayRule(Rule):
    id = RULE_ID
    severity_hint = "critical"

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        reused_signature = bool(ctx.facts.get("signature_reused"))
        nonce_count = int(ctx.facts.get("nonce_occurrences", 0))
        chain_bound = bool(ctx.facts.get("chain_id_bound", True))
        if not reused_signature or nonce_count < 2 or chain_bound:
            return []
        tx_hashes = tuple(str(item) for item in ctx.facts.get("tx_hashes", ()))
        return [
            Finding(
                id=new_finding_id(),
                source=FindingSource.LAB,
                severity=FindingSeverity.CRITICAL,
                confidence=0.97,
                title="Web3 transaction signature is replayable across executions",
                description=(
                    "The same signature and nonce were accepted without binding "
                    "the authorization to a chain identifier."
                ),
                host=ctx.subject,
                evidence=(
                    "signature_reused=true",
                    f"nonce_occurrences={nonce_count}",
                    "chain_id_bound=false",
                    *tx_hashes,
                ),
                tags=frozenset({"web3", "transaction-replay", "smart-contract"}),
                metadata={"scenario": "web3-transaction-replay"},
            )
        ]


def register(registry: RuleRegistry) -> Web3ReplayRule:
    rule = Web3ReplayRule()
    registry.register(rule)
    return rule


def demo_context(subject: str = "lab-target-01") -> RuleContext:
    return RuleContext(
        subject=subject,
        facts={
            "signature_reused": True,
            "nonce_occurrences": 2,
            "chain_id_bound": False,
            "tx_hashes": ("0xfixture01", "0xfixture02"),
        },
    )


def benign_context(subject: str = "lab-target-01") -> RuleContext:
    return RuleContext(
        subject=subject,
        facts={
            "signature_reused": False,
            "nonce_occurrences": 1,
            "chain_id_bound": True,
        },
    )
