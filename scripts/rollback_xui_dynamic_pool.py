#!/usr/bin/env python3
"""Remove only the additive Aimili dynamic-pool x-ui configuration."""

from __future__ import annotations

import argparse
import copy
import json
import sqlite3
from pathlib import Path
from typing import Any


TARGET_TAG = "in-10083-tcp"
POOL_OUTBOUND_TAG = "aimili-dynamic-pool"


def _remove_pool_config(config: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(config)
    if "outbounds" in result:
        result["outbounds"] = [
            item for item in result.get("outbounds", [])
            if item.get("tag") != POOL_OUTBOUND_TAG
        ]
    routing = result.get("routing")
    if isinstance(routing, dict):
        routing["rules"] = [
            rule for rule in routing.get("rules", [])
            if rule.get("outboundTag") != POOL_OUTBOUND_TAG
            and TARGET_TAG not in (rule.get("inboundTag") or [])
        ]
    if "inbounds" in result:
        result["inbounds"] = [
            item for item in result.get("inbounds", [])
            if item.get("tag") != TARGET_TAG
        ]
    return result


def _table_exists(db: sqlite3.Connection, table: str) -> bool:
    return db.execute(
        "select 1 from sqlite_master where type='table' and name=?", (table,)
    ).fetchone() is not None


def rollback_database(path: Path, dry_run: bool = False) -> dict[str, Any]:
    db = sqlite3.connect(str(path), timeout=20)
    db.row_factory = sqlite3.Row
    try:
        db.execute("begin immediate")
        inbound = db.execute(
            "select id from inbounds where tag=?", (TARGET_TAG,)
        ).fetchone()
        removed_inbound = int(inbound[0]) if inbound else None
        if inbound:
            inbound_id = int(inbound[0])
            client_ids = []
            if _table_exists(db, "client_inbounds"):
                client_ids = [
                    int(row[0])
                    for row in db.execute(
                        "select client_id from client_inbounds where inbound_id=?",
                        (inbound_id,),
                    ).fetchall()
                ]
            for table in ("client_traffics", "client_inbounds"):
                if _table_exists(db, table):
                    db.execute(f"delete from {table} where inbound_id=?", (inbound_id,))
            db.execute("delete from inbounds where id=?", (inbound_id,))
            if client_ids and _table_exists(db, "clients"):
                for client_id in client_ids:
                    still_linked = db.execute(
                        "select 1 from client_inbounds where client_id=? limit 1",
                        (client_id,),
                    ).fetchone()
                    if still_linked is None:
                        db.execute("delete from clients where id=?", (client_id,))

        template_row = db.execute(
            "select value from settings where key='xrayTemplateConfig'"
        ).fetchone()
        if template_row:
            template = _remove_pool_config(json.loads(template_row[0]))
            db.execute(
                "update settings set value=? where key='xrayTemplateConfig'",
                (json.dumps(template, ensure_ascii=False, separators=(",", ":")),),
            )
        if dry_run:
            db.rollback()
        else:
            db.commit()
        return {
            "dry_run": dry_run,
            "removed_inbound_id": removed_inbound,
            "template_updated": bool(template_row),
        }
    finally:
        db.close()


def rollback_runtime(path: Path, dry_run: bool = False) -> dict[str, Any]:
    config = json.loads(path.read_text(encoding="utf-8"))
    cleaned = _remove_pool_config(config)
    changed = cleaned != config
    if changed and not dry_run:
        temporary = path.with_suffix(path.suffix + ".rollback-tmp")
        temporary.write_text(
            json.dumps(cleaned, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        temporary.replace(path)
    return {
        "dry_run": dry_run,
        "changed": changed,
        "inbound_count": len(cleaned.get("inbounds", [])),
        "outbound_tags": [item.get("tag") for item in cleaned.get("outbounds", [])],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, required=True)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    result = {
        "database": rollback_database(args.db, args.dry_run),
        "runtime": rollback_runtime(args.runtime, args.dry_run),
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
