#!/usr/bin/env python3
"""Add an isolated x-ui canary inbound for the Aimili dynamic pool.

The existing aimili-vpngate outbound and its routing rules are preserved.
The script updates both x-ui's template and runtime JSON so a later panel
reload does not discard the additive configuration.
"""

from __future__ import annotations

import argparse
import copy
import json
import sqlite3
import uuid
from pathlib import Path
from typing import Any


SOURCE_TAG = "in-10081-tcp"
TARGET_TAG = "in-10083-tcp"
TARGET_PORT = 10083
TARGET_REMARK = "Aimili-Dynamic-Pool-Test"
POOL_OUTBOUND_TAG = "aimili-dynamic-pool"
POOL_PORT = 17928
TARGET_WS_PATH = "/ws-isp-7899-7f4d9c2a"


def _insert_row(db: sqlite3.Connection, table: str, row: dict[str, Any]) -> int:
    columns = list(row)
    placeholders = ",".join("?" for _ in columns)
    cursor = db.execute(
        f"insert into {table} ({','.join(columns)}) values ({placeholders})",
        [row[column] for column in columns],
    )
    return int(cursor.lastrowid)


def _load_template(db: sqlite3.Connection) -> dict[str, Any]:
    value = db.execute("select value from settings where key='xrayTemplateConfig'").fetchone()
    if not value:
        raise RuntimeError("xrayTemplateConfig is missing")
    return json.loads(value[0])


def _clone_clients(
    db: sqlite3.Connection,
    source_inbound_id: int,
    target_inbound_id: int,
    source_settings: dict[str, Any],
) -> dict[str, Any]:
    client_rows = db.execute(
        "select c.* from clients c join client_inbounds ci on ci.client_id=c.id "
        "where ci.inbound_id=? order by c.id",
        (source_inbound_id,),
    ).fetchall()
    if not client_rows:
        raise RuntimeError("source inbound has no database clients")

    columns = [item[1] for item in db.execute("pragma table_info(clients)")]
    source_clients = source_settings.get("clients") or []
    if len(source_clients) != len(client_rows):
        raise RuntimeError("source database clients and inbound settings clients differ")

    new_settings_clients: list[dict[str, Any]] = []
    for source_row, source_client in zip(client_rows, source_clients):
        row = dict(zip(columns, source_row))
        old_id = int(row.pop("id"))
        new_id = str(uuid.uuid4())
        old_email = str(row.get("email") or source_client.get("email") or old_id)
        new_email = f"pool-{old_email}"
        row.update(
            id=None,
            uuid=new_id,
            email=new_email,
            sub_id="",
            created_at=0,
            updated_at=0,
        )
        row.pop("id", None)
        client_id = _insert_row(db, "clients", row)
        client_settings = copy.deepcopy(source_client)
        client_settings.update(id=new_id, email=new_email)
        new_settings_clients.append(client_settings)
        _insert_row(
            db,
            "client_inbounds",
            {"client_id": client_id, "inbound_id": target_inbound_id, "flow_override": "", "created_at": 0},
        )
        _insert_row(
            db,
            "client_traffics",
            {
                "inbound_id": target_inbound_id,
                "enable": int(row.get("enable") or 1),
                "email": new_email,
                "up": 0,
                "down": 0,
                "expiry_time": int(row.get("expiry_time") or 0),
                "total": int(row.get("total_gb") or 0),
                "reset": int(row.get("reset") or 0),
                "last_online": 0,
            },
        )
    source_settings["clients"] = new_settings_clients
    return source_settings


def _pool_users(username: str, password: str) -> list[dict[str, str]]:
    username = str(username or "").strip()
    password = str(password or "").strip()
    if bool(username) != bool(password):
        raise ValueError("pool username and password must be supplied together")
    return [{"user": username, "pass": password}] if username and password else []


def _upsert_pool_config(
    config: dict[str, Any],
    pool_port: int,
    username: str = "",
    password: str = "",
) -> None:
    if not 1024 <= int(pool_port) <= 65535:
        raise ValueError("pool port must be between 1024 and 65535")
    users = _pool_users(username, password)
    outbounds = config.setdefault("outbounds", [])
    outbound = next((item for item in outbounds if item.get("tag") == POOL_OUTBOUND_TAG), None)
    if outbound is None:
        outbound = {"tag": POOL_OUTBOUND_TAG, "protocol": "socks", "settings": {}}
        outbounds.append(outbound)
    outbound["protocol"] = "socks"
    settings = outbound.setdefault("settings", {})
    servers = settings.setdefault("servers", [])
    if not servers or not isinstance(servers[0], dict):
        servers.insert(0, {})
    server = servers[0]
    server.update(address="127.0.0.1", port=int(pool_port), users=users)
    settings["servers"] = servers[:1]


def _append_pool_config(
    config: dict[str, Any],
    pool_port: int,
    username: str = "",
    password: str = "",
) -> None:
    _upsert_pool_config(config, pool_port, username, password)
    if any(rule.get("inboundTag") == [TARGET_TAG] for rule in config.get("routing", {}).get("rules", [])):
        raise RuntimeError(f"target route {TARGET_TAG} already exists")
    config.setdefault("routing", {}).setdefault("rules", []).insert(
        0, {"type": "field", "inboundTag": [TARGET_TAG], "outboundTag": POOL_OUTBOUND_TAG}
    )


def _set_ws_path(value: str) -> str:
    settings = json.loads(value or "{}")
    ws_settings = settings.setdefault("wsSettings", {})
    ws_settings["path"] = TARGET_WS_PATH
    return json.dumps(settings, ensure_ascii=False, separators=(",", ":"))


def _set_runtime_ws_path(inbound: dict[str, Any]) -> None:
    stream_settings = inbound.get("streamSettings")
    if not isinstance(stream_settings, dict):
        return
    stream_settings.setdefault("wsSettings", {})["path"] = TARGET_WS_PATH


def _build_candidate(
    db: sqlite3.Connection,
    runtime: dict[str, Any],
    pool_port: int,
    pool_username: str,
    pool_password: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    source = db.execute("select * from inbounds where tag=?", (SOURCE_TAG,)).fetchone()
    if not source:
        raise RuntimeError(f"source inbound {SOURCE_TAG} is missing")
    columns = [item[1] for item in db.execute("pragma table_info(inbounds)")]
    source_row = dict(zip(columns, source))
    if db.execute("select 1 from inbounds where tag=?", (TARGET_TAG,)).fetchone():
        raise RuntimeError(f"target inbound {TARGET_TAG} already exists")
    if db.execute("select 1 from inbounds where port=?", (TARGET_PORT,)).fetchone():
        raise RuntimeError(f"target port {TARGET_PORT} already exists")

    source_settings = json.loads(source_row["settings"])
    source_row["stream_settings"] = _set_ws_path(source_row.get("stream_settings", "{}"))
    source_row.pop("id", None)
    source_row.update(
        port=TARGET_PORT,
        remark=TARGET_REMARK,
        tag=TARGET_TAG,
        up=0,
        down=0,
        total=0,
        settings=json.dumps(source_settings, separators=(",", ":")),
    )
    target_id = _insert_row(db, "inbounds", source_row)
    cloned_settings = _clone_clients(db, int(source[columns.index("id")]), target_id, source_settings)
    db.execute(
        "update inbounds set settings=? where id=?",
        (json.dumps(cloned_settings, separators=(",", ":")), target_id),
    )

    template = _load_template(db)
    source_runtime = next(
        (item for item in runtime.get("inbounds", []) if item.get("tag") == SOURCE_TAG),
        None,
    )
    if source_runtime is None:
        raise RuntimeError(f"runtime template inbound {SOURCE_TAG} is missing")
    _append_pool_config(template, pool_port, pool_username, pool_password)
    _append_pool_config(runtime, pool_port, pool_username, pool_password)
    target_runtime = copy.deepcopy(source_runtime)
    target_runtime.update(
        tag=TARGET_TAG,
        port=TARGET_PORT,
        remark=TARGET_REMARK,
        settings=cloned_settings,
    )
    _set_runtime_ws_path(target_runtime)
    runtime["inbounds"].append(target_runtime)
    return template, runtime


def apply(
    db_path: Path,
    runtime_path: Path,
    dry_run: bool,
    pool_port: int = POOL_PORT,
    pool_username: str = "",
    pool_password: str = "",
) -> dict[str, Any]:
    db = sqlite3.connect(str(db_path), timeout=20)
    db.row_factory = sqlite3.Row
    try:
        db.execute("begin immediate")
        runtime = json.loads(runtime_path.read_text(encoding="utf-8"))
        template, runtime = _build_candidate(
            db, runtime, pool_port, pool_username, pool_password
        )
        serialized = json.dumps(template, ensure_ascii=False, separators=(",", ":"))
        db.execute("update settings set value=? where key='xrayTemplateConfig'", (serialized,))
        if dry_run:
            db.rollback()
        else:
            db.commit()
            runtime_path.write_text(
                json.dumps(runtime, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
        return {
            "dry_run": dry_run,
            "target_tag": TARGET_TAG,
            "target_port": TARGET_PORT,
            "pool_outbound": POOL_OUTBOUND_TAG,
            "pool_port": int(pool_port),
            "pool_auth_enabled": bool(pool_username and pool_password),
            "inbound_count": len(runtime.get("inbounds", [])),
            "outbound_tags": [item.get("tag") for item in runtime.get("outbounds", [])],
            "aimili_outbound": next(item for item in runtime["outbounds"] if item.get("tag") == "aimili-vpngate"),
        }
    finally:
        db.close()


def sync_pool(
    db_path: Path,
    runtime_path: Path,
    dry_run: bool,
    pool_port: int = POOL_PORT,
    pool_username: str = "",
    pool_password: str = "",
) -> dict[str, Any]:
    """Update an existing Aimili pool outbound without touching inbounds."""

    db = sqlite3.connect(str(db_path), timeout=20)
    try:
        db.execute("begin immediate")
        runtime = json.loads(runtime_path.read_text(encoding="utf-8"))
        template = _load_template(db)
        _upsert_pool_config(template, pool_port, pool_username, pool_password)
        _upsert_pool_config(runtime, pool_port, pool_username, pool_password)
        db.execute(
            "update settings set value=? where key='xrayTemplateConfig'",
            (json.dumps(template, ensure_ascii=False, separators=(",", ":")),),
        )
        if dry_run:
            db.rollback()
        else:
            db.commit()
            temporary = runtime_path.with_suffix(runtime_path.suffix + ".tmp")
            temporary.write_text(
                json.dumps(runtime, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            temporary.replace(runtime_path)
        pool = next(item for item in runtime.get("outbounds", []) if item.get("tag") == POOL_OUTBOUND_TAG)
        server = pool["settings"]["servers"][0]
        return {
            "dry_run": dry_run,
            "pool_outbound": POOL_OUTBOUND_TAG,
            "pool_port": server.get("port"),
            "pool_auth_enabled": bool(server.get("users")),
            "inbound_count": len(runtime.get("inbounds", [])),
        }
    finally:
        db.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", type=Path, required=True)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--pool-port", type=int, default=POOL_PORT)
    parser.add_argument("--pool-user", default="")
    parser.add_argument("--pool-pass", default="")
    parser.add_argument("--sync-pool", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    operation = sync_pool if args.sync_pool else apply
    print(json.dumps(
        operation(
            args.db,
            args.runtime,
            args.dry_run,
            args.pool_port,
            args.pool_user,
            args.pool_pass,
        ),
        ensure_ascii=False,
        indent=2,
    ))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
