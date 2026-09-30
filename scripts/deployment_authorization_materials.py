"""Offline acceptance materials only: no HTTP, database, deploy or delete code.

Exit 0: materials prepared / cleanup dry-run printed. Exit 2: invalid input.
Exit 4: deployment unverified (including when all decision fields are filled).
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "docs/validation/deployment-authorization.example.json"
CASE_IDS = (
    "OIDC-01", "OIDC-02", "OIDC-03", "OIDC-04", "OIDC-05", "OIDC-06",
    "AUTH-01", "AUTH-02", "AUTH-03", "AUTH-04",
    "MULTI-01", "MULTI-02", "MULTI-03", "MULTI-04",
    "AUDIT-01", "AUDIT-02", "AUDIT-03", "RECOVERY-01", "RECOVERY-02",
)
CAMPAIGN = re.compile(r"authval-[a-z0-9]{8,24}\Z")


def read_json(path: Path) -> dict[str, Any]:
    data = path.read_bytes()
    if len(data) > 131072:
        raise ValueError("material file exceeds size limit")
    value = json.loads(data.decode("utf-8-sig"))
    if not isinstance(value, dict):
        raise TypeError("material must be an object")
    return value


def write_json(path: Path, value: object) -> None:
    with path.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def synthetic_resources(campaign: str) -> dict[str, object]:
    if not CAMPAIGN.fullmatch(campaign):
        raise ValueError("campaign must be authval- plus 8-24 lowercase alphanumeric characters")
    tenants = [f"{campaign}-a", f"{campaign}-b"]
    return {
        "campaign": campaign, "synthetic_only": True, "created_in_environment": False,
        "tenants": tenants,
        "accounts": [f"{tenant}-{role}" for tenant in tenants
                     for role in ("viewer", "operator", "admin", "auditor")],
        "project_names": [f"{tenant}-project" for tenant in tenants],
        "idempotency_key": f"{campaign}-same-key",
        "body_canary": f"SYNTHETIC_BODY_{campaign}",
        "actual_resource_ids": [],
    }


def prepare(out: Path, campaign: str) -> None:
    resources = synthetic_resources(campaign)
    config = read_json(TEMPLATE)
    config["campaign"] = campaign
    out.mkdir(parents=True, exist_ok=False)
    write_json(out / "config.json", config)
    write_json(out / "synthetic-resources.json", resources)
    write_json(out / "evidence-template.json", {
        "campaign": campaign, "deployment_status": "not_verified",
        "source_commit": None, "workspace_sha256": None,
        "environment_inventory_reference": None,
        "cases": [{
            "id": case, "status": "not_run", "executor": None, "timestamp_utc": None,
            "instance_ids": [], "request_ids": [], "actual_summary": None,
            "sanitized_evidence_references": [], "cleanup_receipt_reference": None,
        } for case in CASE_IDS],
    })
    write_json(out / "material-status.json", {
        "local_material_status": "prepared", "deployment_status": "not_verified",
        "external_resources_created": False, "credentials_generated": False,
    })


def check_config(path: Path) -> dict[str, object]:
    config = read_json(path)
    template = read_json(TEMPLATE)
    if set(config) != set(template) or config.get("schema_version") != 1:
        raise ValueError("unexpected configuration schema")
    if config.get("environment_kind") != "isolated-test":
        raise ValueError("only isolated-test planning is accepted")
    campaign = config.get("campaign")
    if not isinstance(campaign, str) or not CAMPAIGN.fullmatch(campaign):
        raise ValueError("invalid campaign")
    decisions = config.get("decisions")
    if not isinstance(decisions, dict) or set(decisions) != set(template["decisions"]):
        raise ValueError("decision fields differ from template")
    if any(value is not None and not isinstance(value, str) for value in decisions.values()):
        raise ValueError("decisions require text descriptions or null; never credentials")
    pending = sorted(key for key, value in decisions.items() if not value or not value.strip())
    # Never echo values: this is a metadata checklist, not validation of endpoints/secrets.
    return {
        "decision_metadata_complete": not pending, "pending_decisions": pending,
        "deployment_status": "not_verified", "exit_code": 4,
        "reason": "No real OIDC/PostgreSQL/multi-instance execution evidence collected",
    }


def cleanup_plan(bundle: Path) -> dict[str, object]:
    stored = read_json(bundle / "synthetic-resources.json")
    campaign = stored.get("campaign")
    if not isinstance(campaign, str):
        raise TypeError("invalid campaign")
    expected = synthetic_resources(campaign)
    if stored != expected:
        raise ValueError("synthetic resource manifest changed; refusing expanded scope")
    return {
        "dry_run": True, "deleted": 0, "campaign": campaign,
        "planned_logical_resources": expected,
        "required_before_real_cleanup": [
            "Stop test requests/workers and verify isolated environment identity",
            "Inventory exact created IDs and tenant ownership; never delete by prefix alone",
            "Verify backup/restore receipt and preserve sanitized evidence",
            "Have operator review exact accounts, rows and artifact keys before cleanup",
        ],
        "reason": "This tool has no apply/delete mode and created no external resources",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prepare_parser = commands.add_parser("prepare")
    prepare_parser.add_argument("--output-dir", type=Path, required=True)
    prepare_parser.add_argument("--campaign", required=True)
    check_parser = commands.add_parser("check")
    check_parser.add_argument("--config", type=Path, required=True)
    cleanup_parser = commands.add_parser("cleanup-plan")
    cleanup_parser.add_argument("--bundle", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "prepare":
            prepare(args.output_dir, args.campaign)
            result: dict[str, object] = {"local_material_status": "prepared", "deployment_status": "not_verified"}
        elif args.command == "check":
            result = check_config(args.config)
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 4
        else:
            result = cleanup_plan(args.bundle)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except (OSError, TypeError, ValueError):
        # Do not dump paths, config values or possible accidentally supplied secrets.
        print(json.dumps({"status": "invalid_material", "exit_code": 2}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
