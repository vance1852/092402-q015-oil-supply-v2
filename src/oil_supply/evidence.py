"""审计证据包的快照采集、断点续作、导出与验证。

证据任务针对一个根对象（分配运行、转运或情景结果）沿真实引用收集报价修订、
设施与线路版本、停运记录、库存批次、操作决定和对应审计片段。任务创建时在
事务内捕获各表高水位线与文本主键清单作为快照边界，之后的新写入不会混入；
证据内容只取不可变列，用户资料按审计权限脱敏。任务游标与条目持久化在
SQLite，中断后可以从上次步骤续作。清单为规范化 JSON 并按条目键稳定排序，
逐项与整包计算 SHA-256；验证时分别报告缺失引用、摘要不符与审计断链。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any, Iterable, Mapping

from .clock import SystemClock, utc_text
from .errors import InvalidState, NotFound, SupplyError, ValidationFailed
from .planning import canonical_json, digest
from .storage import connect, transaction


FORMAT = "oil-supply-evidence/v1"
ROOT_TYPES = ("allocation", "transfer", "scenario_run")
REDACTION_MODES = ("masked", "unmasked")

# 证据类型 -> (来源表, 主键字段)
REFERENCES = {
    "allocation_run": ("allocation_runs", "allocation_id"),
    "route": ("routes", "route_id"),
    "facility": ("facilities", "facility_id"),
    "outage": ("route_outages", "outage_id"),
    "nomination": ("nominations", "nomination_id"),
    "inventory_lot": ("inventory_lots", "lot_id"),
    "inventory_adjustment": ("inventory_adjustments", "adjustment_id"),
    "transfer": ("transfers", "transfer_id"),
    "scenario": ("supply_scenarios", "scenario_id"),
    "scenario_run": ("scenario_runs", "run_id"),
    "quote": ("price_index_quotes", "quote_id"),
    "audit_event": ("supply_audit_events", "event_id"),
    "user": ("supply_users", "user_id"),
}

# 证据类型 -> 快照边界键（自增表为高水位整数，文本主键表为快照清单）
SNAPSHOT_KEY = {
    "allocation_run": "allocation_id",
    "outage": "outage_id",
    "inventory_adjustment": "adjustment_id",
    "scenario_run": "run_id",
    "quote": "quote_id",
    "audit_event": "event_id",
    "route": "routes",
    "facility": "facilities",
    "nomination": "nominations",
    "inventory_lot": "lots",
    "transfer": "transfers",
    "scenario": "scenarios",
}

# 证据类型 -> 进入证据内容的不可变列（任务启动后的状态推进不会混入）
ITEM_FIELDS = {
    "allocation_run": ("allocation_id", "route_id", "service_date", "input_sha256",
                       "available_capacity", "result_json", "created_by", "created_at"),
    "route": ("route_id", "origin_id", "destination_id", "product", "daily_capacity",
              "loss_basis_points", "transit_hours", "revision", "created_at"),
    "facility": ("facility_id", "name", "kind", "timezone", "capacity_barrels", "created_at"),
    "outage": ("outage_id", "route_id", "starts_at", "ends_at", "capacity_percent",
               "reason", "state", "created_by", "created_at"),
    "nomination": ("nomination_id", "route_id", "shipper_id", "service_date",
                   "requested_barrels", "priority", "idempotency_key", "submitted_by", "submitted_at"),
    "inventory_lot": ("lot_id", "facility_id", "product", "grade", "quantity_barrels",
                      "unit_cost_usd", "received_at", "created_by", "created_at"),
    "inventory_adjustment": ("adjustment_id", "lot_id", "delta_barrels", "reason_code",
                             "note", "actor_id", "created_at"),
    "transfer": ("transfer_id", "nomination_id", "inventory_lot_id", "loaded_barrels",
                 "expected_delivered_barrels", "departed_at", "created_by", "created_at"),
    "scenario": ("scenario_id", "name", "definition_json", "content_sha256", "created_by", "created_at"),
    "scenario_run": ("run_id", "scenario_id", "as_of_date", "input_sha256",
                     "result_json", "created_by", "created_at"),
    "quote": ("quote_id", "price_index", "trade_date", "close_usd", "source_revision",
              "observed_at", "supersedes_quote_id", "recorded_by", "recorded_at"),
    "audit_event": ("event_id", "entity_type", "entity_id", "event_type", "actor_id",
                    "payload_json", "previous_hash", "event_hash", "created_at"),
    "user": ("user_id", "role", "display_name"),
}

# JSON 文本列 -> 证据内容中的字段名
JSON_FIELDS = {
    "allocation_run": {"result_json": "result"},
    "scenario_run": {"result_json": "result"},
    "scenario": {"definition_json": "definition"},
    "audit_event": {"payload_json": "payload"},
}

ACTOR_FIELDS = ("created_by", "submitted_by", "recorded_by", "actor_id")

STEP_PLANS = {
    "allocation": ("root", "route", "facilities", "outages", "nominations", "audit_events", "users"),
    "transfer": ("root", "nomination", "route", "inventory", "facilities",
                 "adjustments", "allocations", "outages", "audit_events", "users"),
    "scenario_run": ("root", "scenario", "quotes", "routes", "inventory",
                     "facilities", "audit_events", "users"),
}


def redacted_display_name(user_id: str) -> str:
    """为用户编号生成跨证据包稳定的脱敏假名。"""
    return "redacted-" + hashlib.sha256(f"supply-user:{user_id}".encode("utf-8")).hexdigest()[:12]


def project_item(item_type: str, row: Mapping[str, Any], redaction: str = "masked") -> dict[str, Any]:
    """把数据库行投影为只含不可变列的证据内容。"""
    content: dict[str, Any] = {}
    json_fields = JSON_FIELDS.get(item_type, {})
    for field in ITEM_FIELDS[item_type]:
        target = json_fields.get(field)
        if target is not None:
            content[target] = json.loads(row[field])
        else:
            content[field] = row[field]
    if item_type == "user" and redaction != "unmasked":
        content["display_name"] = redacted_display_name(content["user_id"])
    return content


def capture_snapshot(connection: sqlite3.Connection) -> dict[str, Any]:
    """在任务创建事务内记录各表高水位线与文本主键清单。"""
    def max_id(table: str, column: str) -> int:
        row = connection.execute(f"SELECT max({column}) FROM {table}").fetchone()
        return int(row[0] or 0)

    def identifiers(table: str, column: str) -> list[str]:
        return [row[0] for row in connection.execute(f"SELECT {column} FROM {table} ORDER BY {column}")]

    return {
        "allocation_id": max_id("allocation_runs", "allocation_id"),
        "adjustment_id": max_id("inventory_adjustments", "adjustment_id"),
        "event_id": max_id("supply_audit_events", "event_id"),
        "outage_id": max_id("route_outages", "outage_id"),
        "quote_id": max_id("price_index_quotes", "quote_id"),
        "run_id": max_id("scenario_runs", "run_id"),
        "facilities": identifiers("facilities", "facility_id"),
        "lots": identifiers("inventory_lots", "lot_id"),
        "nominations": identifiers("nominations", "nomination_id"),
        "routes": identifiers("routes", "route_id"),
        "scenarios": identifiers("supply_scenarios", "scenario_id"),
        "transfers": identifiers("transfers", "transfer_id"),
    }


def _allowed(snapshot: Mapping[str, Any], item_type: str, primary_key: object) -> bool:
    bound = snapshot.get(SNAPSHOT_KEY.get(item_type, ""))
    if bound is None:
        return True
    if isinstance(bound, list):
        return str(primary_key) in bound
    return int(primary_key) <= int(bound)


def _fetch(connection: sqlite3.Connection, item_type: str, primary_key: object) -> sqlite3.Row | None:
    table, field = REFERENCES[item_type]
    return connection.execute(f"SELECT * FROM {table} WHERE {field}=?", (primary_key,)).fetchone()


def _collect(
    connection: sqlite3.Connection,
    task_id: str,
    snapshot: Mapping[str, Any],
    item_type: str,
    row: sqlite3.Row | None,
    redaction: str,
) -> bool:
    if row is None:
        return False
    content = project_item(item_type, row, redaction)
    primary_key = content[REFERENCES[item_type][1]]
    if not _allowed(snapshot, item_type, primary_key):
        return False
    key = f"{item_type}:{primary_key}"
    connection.execute(
        "INSERT OR REPLACE INTO evidence_items(task_id,item_key,item_type,content_json,sha256) "
        "VALUES(?,?,?,?,?)",
        (task_id, key, item_type, canonical_json(content), digest(content)),
    )
    return True


def _root_row(connection: sqlite3.Connection, task: Mapping[str, Any]) -> sqlite3.Row:
    root_type = task["root_type"]
    if root_type == "allocation":
        row = _fetch(connection, "allocation_run", int(task["root_id"]))
        message = "分配运行不存在"
    elif root_type == "transfer":
        row = _fetch(connection, "transfer", task["root_id"])
        message = "转运不存在"
    else:
        row = _fetch(connection, "scenario_run", int(task["root_id"]))
        message = "情景运行不存在"
    if row is None:
        raise InvalidState(message)
    return row


def _collect_facilities(
    connection: sqlite3.Connection,
    task: Mapping[str, Any],
    snapshot: Mapping[str, Any],
    facility_ids: Iterable[str],
) -> None:
    for facility_id in sorted(set(facility_ids)):
        _collect(connection, task["task_id"], snapshot, "facility",
                 _fetch(connection, "facility", facility_id), task["redaction"])


def _collect_route_window_outages(
    connection: sqlite3.Connection,
    task: Mapping[str, Any],
    snapshot: Mapping[str, Any],
    route_id: str,
    service_date: str,
) -> None:
    start = service_date + "T00:00:00Z"
    end = service_date + "T23:59:59Z"
    rows = connection.execute(
        "SELECT * FROM route_outages WHERE route_id=? AND state IN ('announced','active') "
        "AND starts_at<=? AND (ends_at IS NULL OR ends_at>=?) AND outage_id<=? ORDER BY outage_id",
        (route_id, end, start, snapshot["outage_id"]),
    ).fetchall()
    for row in rows:
        _collect(connection, task["task_id"], snapshot, "outage", row, task["redaction"])


def _audit_references(connection: sqlite3.Connection, task: Mapping[str, Any]) -> list[tuple[str, str]]:
    root_type = task["root_type"]
    root = _root_row(connection, task)
    if root_type == "allocation":
        references = {("route", root["route_id"])}
        for entry in json.loads(root["result_json"]).get("allocations", []):
            references.add(("nomination", entry["nomination_id"]))
        return sorted(references)
    if root_type == "transfer":
        nomination = _fetch(connection, "nomination", root["nomination_id"])
        references = {
            ("transfer", root["transfer_id"]),
            ("nomination", root["nomination_id"]),
            ("inventory_lot", root["inventory_lot_id"]),
        }
        if nomination is not None:
            references.add(("route", nomination["route_id"]))
        return sorted(references)
    return [("scenario", root["scenario_id"])]


def _audit_events_step(connection: sqlite3.Connection, task: Mapping[str, Any], snapshot: Mapping[str, Any]) -> None:
    references = _audit_references(connection, task)
    if not references:
        return
    where = " OR ".join("(entity_type=? AND entity_id=?)" for _ in references)
    params = [value for reference in references for value in reference]
    rows = connection.execute(
        f"SELECT * FROM supply_audit_events WHERE event_id<=? AND ({where}) ORDER BY event_id",
        (snapshot["event_id"], *params),
    ).fetchall()
    for row in rows:
        _collect(connection, task["task_id"], snapshot, "audit_event", row, task["redaction"])


def _users_step(connection: sqlite3.Connection, task: Mapping[str, Any], snapshot: Mapping[str, Any]) -> None:
    rows = connection.execute(
        "SELECT content_json FROM evidence_items WHERE task_id=?", (task["task_id"],)
    ).fetchall()
    actors: set[str] = set()
    for row in rows:
        content = json.loads(row["content_json"])
        for field in ACTOR_FIELDS:
            value = content.get(field)
            if isinstance(value, str) and value:
                actors.add(value)
    for user_id in sorted(actors):
        _collect(connection, task["task_id"], snapshot, "user",
                 _fetch(connection, "user", user_id), task["redaction"])


def _allocation_root(connection: sqlite3.Connection, task: Mapping[str, Any], snapshot: Mapping[str, Any]) -> None:
    _collect(connection, task["task_id"], snapshot, "allocation_run",
             _root_row(connection, task), task["redaction"])


def _allocation_route(connection: sqlite3.Connection, task: Mapping[str, Any], snapshot: Mapping[str, Any]) -> None:
    root = _root_row(connection, task)
    _collect(connection, task["task_id"], snapshot, "route",
             _fetch(connection, "route", root["route_id"]), task["redaction"])


def _allocation_facilities(connection: sqlite3.Connection, task: Mapping[str, Any], snapshot: Mapping[str, Any]) -> None:
    root = _root_row(connection, task)
    route = _fetch(connection, "route", root["route_id"])
    if route is not None:
        _collect_facilities(connection, task, snapshot, (route["origin_id"], route["destination_id"]))


def _allocation_outages(connection: sqlite3.Connection, task: Mapping[str, Any], snapshot: Mapping[str, Any]) -> None:
    root = _root_row(connection, task)
    _collect_route_window_outages(connection, task, snapshot, root["route_id"], root["service_date"])


def _allocation_nominations(connection: sqlite3.Connection, task: Mapping[str, Any], snapshot: Mapping[str, Any]) -> None:
    root = _root_row(connection, task)
    for entry in json.loads(root["result_json"]).get("allocations", []):
        _collect(connection, task["task_id"], snapshot, "nomination",
                 _fetch(connection, "nomination", entry["nomination_id"]), task["redaction"])


def _transfer_root(connection: sqlite3.Connection, task: Mapping[str, Any], snapshot: Mapping[str, Any]) -> None:
    _collect(connection, task["task_id"], snapshot, "transfer",
             _root_row(connection, task), task["redaction"])


def _transfer_nomination(connection: sqlite3.Connection, task: Mapping[str, Any], snapshot: Mapping[str, Any]) -> None:
    root = _root_row(connection, task)
    _collect(connection, task["task_id"], snapshot, "nomination",
             _fetch(connection, "nomination", root["nomination_id"]), task["redaction"])


def _transfer_route(connection: sqlite3.Connection, task: Mapping[str, Any], snapshot: Mapping[str, Any]) -> None:
    root = _root_row(connection, task)
    nomination = _fetch(connection, "nomination", root["nomination_id"])
    if nomination is not None:
        _collect(connection, task["task_id"], snapshot, "route",
                 _fetch(connection, "route", nomination["route_id"]), task["redaction"])


def _transfer_inventory(connection: sqlite3.Connection, task: Mapping[str, Any], snapshot: Mapping[str, Any]) -> None:
    root = _root_row(connection, task)
    _collect(connection, task["task_id"], snapshot, "inventory_lot",
             _fetch(connection, "inventory_lot", root["inventory_lot_id"]), task["redaction"])


def _transfer_facilities(connection: sqlite3.Connection, task: Mapping[str, Any], snapshot: Mapping[str, Any]) -> None:
    root = _root_row(connection, task)
    facility_ids: list[str] = []
    nomination = _fetch(connection, "nomination", root["nomination_id"])
    if nomination is not None:
        route = _fetch(connection, "route", nomination["route_id"])
        if route is not None:
            facility_ids.extend((route["origin_id"], route["destination_id"]))
    lot = _fetch(connection, "inventory_lot", root["inventory_lot_id"])
    if lot is not None:
        facility_ids.append(lot["facility_id"])
    _collect_facilities(connection, task, snapshot, facility_ids)


def _transfer_adjustments(connection: sqlite3.Connection, task: Mapping[str, Any], snapshot: Mapping[str, Any]) -> None:
    root = _root_row(connection, task)
    rows = connection.execute(
        "SELECT * FROM inventory_adjustments WHERE lot_id=? AND adjustment_id<=? ORDER BY adjustment_id",
        (root["inventory_lot_id"], snapshot["adjustment_id"]),
    ).fetchall()
    for row in rows:
        _collect(connection, task["task_id"], snapshot, "inventory_adjustment", row, task["redaction"])


def _transfer_allocations(connection: sqlite3.Connection, task: Mapping[str, Any], snapshot: Mapping[str, Any]) -> None:
    root = _root_row(connection, task)
    nomination = _fetch(connection, "nomination", root["nomination_id"])
    if nomination is None:
        return
    rows = connection.execute(
        "SELECT * FROM allocation_runs WHERE route_id=? AND service_date=? AND allocation_id<=? "
        "ORDER BY allocation_id",
        (nomination["route_id"], nomination["service_date"], snapshot["allocation_id"]),
    ).fetchall()
    for row in rows:
        allocations = json.loads(row["result_json"]).get("allocations", [])
        if any(entry["nomination_id"] == root["nomination_id"] for entry in allocations):
            _collect(connection, task["task_id"], snapshot, "allocation_run", row, task["redaction"])


def _transfer_outages(connection: sqlite3.Connection, task: Mapping[str, Any], snapshot: Mapping[str, Any]) -> None:
    root = _root_row(connection, task)
    nomination = _fetch(connection, "nomination", root["nomination_id"])
    if nomination is not None:
        _collect_route_window_outages(connection, task, snapshot, nomination["route_id"], nomination["service_date"])


def _scenario_root(connection: sqlite3.Connection, task: Mapping[str, Any], snapshot: Mapping[str, Any]) -> None:
    _collect(connection, task["task_id"], snapshot, "scenario_run",
             _root_row(connection, task), task["redaction"])


def _scenario_definition(connection: sqlite3.Connection, task: Mapping[str, Any], snapshot: Mapping[str, Any]) -> None:
    root = _root_row(connection, task)
    _collect(connection, task["task_id"], snapshot, "scenario",
             _fetch(connection, "scenario", root["scenario_id"]), task["redaction"])


def _scenario_quotes(connection: sqlite3.Connection, task: Mapping[str, Any], snapshot: Mapping[str, Any]) -> None:
    root = _root_row(connection, task)
    base = connection.execute(
        "SELECT * FROM price_index_quotes WHERE trade_date<=? AND quote_id<=? "
        "ORDER BY trade_date DESC, quote_id DESC LIMIT 1",
        (root["as_of_date"], snapshot["quote_id"]),
    ).fetchone()
    if base is None:
        return
    rows = connection.execute(
        "SELECT * FROM price_index_quotes WHERE price_index=? AND trade_date=? AND quote_id<=? ORDER BY quote_id",
        (base["price_index"], base["trade_date"], snapshot["quote_id"]),
    ).fetchall()
    for row in rows:
        _collect(connection, task["task_id"], snapshot, "quote", row, task["redaction"])


def _scenario_routes(connection: sqlite3.Connection, task: Mapping[str, Any], snapshot: Mapping[str, Any]) -> None:
    root = _root_row(connection, task)
    for entry in json.loads(root["result_json"]).get("routes", []):
        _collect(connection, task["task_id"], snapshot, "route",
                 _fetch(connection, "route", entry["route_id"]), task["redaction"])


def _scenario_inventory_keys(connection: sqlite3.Connection, task: Mapping[str, Any]) -> list[tuple[str, str]]:
    root = _root_row(connection, task)
    keys = []
    for entry in json.loads(root["result_json"]).get("inventory", []):
        facility_id, _, product = entry["inventory_key"].partition(":")
        keys.append((facility_id, product))
    return keys


def _scenario_inventory(connection: sqlite3.Connection, task: Mapping[str, Any], snapshot: Mapping[str, Any]) -> None:
    for facility_id, product in _scenario_inventory_keys(connection, task):
        rows = connection.execute(
            "SELECT * FROM inventory_lots WHERE facility_id=? AND product=? ORDER BY lot_id",
            (facility_id, product),
        ).fetchall()
        for row in rows:
            _collect(connection, task["task_id"], snapshot, "inventory_lot", row, task["redaction"])


def _scenario_facilities(connection: sqlite3.Connection, task: Mapping[str, Any], snapshot: Mapping[str, Any]) -> None:
    root = _root_row(connection, task)
    facility_ids: list[str] = []
    for entry in json.loads(root["result_json"]).get("routes", []):
        route = _fetch(connection, "route", entry["route_id"])
        if route is not None:
            facility_ids.extend((route["origin_id"], route["destination_id"]))
    facility_ids.extend(facility_id for facility_id, _ in _scenario_inventory_keys(connection, task))
    _collect_facilities(connection, task, snapshot, facility_ids)


_STEP_HANDLERS = {
    ("allocation", "root"): _allocation_root,
    ("allocation", "route"): _allocation_route,
    ("allocation", "facilities"): _allocation_facilities,
    ("allocation", "outages"): _allocation_outages,
    ("allocation", "nominations"): _allocation_nominations,
    ("allocation", "audit_events"): _audit_events_step,
    ("allocation", "users"): _users_step,
    ("transfer", "root"): _transfer_root,
    ("transfer", "nomination"): _transfer_nomination,
    ("transfer", "route"): _transfer_route,
    ("transfer", "inventory"): _transfer_inventory,
    ("transfer", "facilities"): _transfer_facilities,
    ("transfer", "adjustments"): _transfer_adjustments,
    ("transfer", "allocations"): _transfer_allocations,
    ("transfer", "outages"): _transfer_outages,
    ("transfer", "audit_events"): _audit_events_step,
    ("transfer", "users"): _users_step,
    ("scenario_run", "root"): _scenario_root,
    ("scenario_run", "scenario"): _scenario_definition,
    ("scenario_run", "quotes"): _scenario_quotes,
    ("scenario_run", "routes"): _scenario_routes,
    ("scenario_run", "inventory"): _scenario_inventory,
    ("scenario_run", "facilities"): _scenario_facilities,
    ("scenario_run", "audit_events"): _audit_events_step,
    ("scenario_run", "users"): _users_step,
}


_ROOT_ITEM_TYPE = {"allocation": "allocation_run", "transfer": "transfer", "scenario_run": "scenario_run"}


def _normalize_root(connection: sqlite3.Connection, root_type: str, root_id: object) -> str:
    if root_type not in ROOT_TYPES:
        raise ValidationFailed("root_type 必须是 allocation、transfer 或 scenario_run")
    text = str(root_id).strip()
    if not text:
        raise ValidationFailed("root_id 不能为空")
    primary_key: object = text
    if root_type in {"allocation", "scenario_run"}:
        try:
            primary_key = int(text)
        except ValueError as exc:
            raise ValidationFailed("root_id 必须是整数编号") from exc
        text = str(primary_key)
    if _fetch(connection, _ROOT_ITEM_TYPE[root_type], primary_key) is None:
        raise NotFound("证据根对象不存在")
    return text


def create_task(
    connection: sqlite3.Connection,
    clock: Any,
    actor_id: str,
    root_type: str,
    root_id: object,
    redaction: str = "masked",
) -> dict[str, Any]:
    """创建证据任务；同一根版本重复申请返回同一任务。"""
    if redaction not in REDACTION_MODES:
        raise ValidationFailed("未知脱敏模式")
    normalized = _normalize_root(connection, root_type, root_id)
    task_id = "evidence-" + hashlib.sha256(f"{root_type}:{normalized}".encode("utf-8")).hexdigest()[:20]
    existing = connection.execute(
        "SELECT task_id FROM evidence_tasks WHERE task_id=?", (task_id,)
    ).fetchone()
    if existing is not None:
        return task_status(connection, task_id, reused=True)
    try:
        with transaction(connection, immediate=True):
            snapshot = capture_snapshot(connection)
            connection.execute(
                "INSERT INTO evidence_tasks(task_id,root_type,root_id,state,cursor,snapshot_json,redaction,"
                "requested_by,created_at) VALUES(?,?,?,'pending',0,?,?,?,?)",
                (task_id, root_type, normalized, canonical_json(snapshot), redaction, actor_id,
                 utc_text(clock.now())),
            )
    except sqlite3.IntegrityError:
        return task_status(connection, task_id, reused=True)
    return task_status(connection, task_id, reused=False)


def task_status(connection: sqlite3.Connection, task_id: str, *, reused: bool | None = None) -> dict[str, Any]:
    row = connection.execute("SELECT * FROM evidence_tasks WHERE task_id=?", (task_id,)).fetchone()
    if row is None:
        raise NotFound("证据任务不存在")
    items = connection.execute(
        "SELECT count(*) FROM evidence_items WHERE task_id=?", (task_id,)
    ).fetchone()[0]
    status: dict[str, Any] = {
        "task_id": row["task_id"],
        "root_type": row["root_type"],
        "root_id": row["root_id"],
        "state": row["state"],
        "cursor": row["cursor"],
        "step_count": len(STEP_PLANS[row["root_type"]]) + 1,
        "items": items,
        "redaction": row["redaction"],
        "package_sha256": row["package_sha256"],
        "error": row["error"],
        "created_at": row["created_at"],
        "started_at": row["started_at"],
        "finished_at": row["finished_at"],
    }
    if reused is not None:
        status["reused"] = reused
    return status


def _finalize(connection: sqlite3.Connection, task: Mapping[str, Any], snapshot: Mapping[str, Any], now: str) -> None:
    items = connection.execute(
        "SELECT item_key,item_type,sha256 FROM evidence_items WHERE task_id=? ORDER BY item_key",
        (task["task_id"],),
    ).fetchall()
    events = [
        json.loads(row["content_json"])
        for row in connection.execute(
            "SELECT content_json FROM evidence_items WHERE task_id=? AND item_type='audit_event'",
            (task["task_id"],),
        ).fetchall()
    ]
    events.sort(key=lambda event: event["event_id"])
    manifest = {
        "format": FORMAT,
        "task_id": task["task_id"],
        "root": {"type": task["root_type"], "id": task["root_id"]},
        "redaction": task["redaction"],
        "snapshot": snapshot,
        "items": [{"key": row["item_key"], "type": row["item_type"], "sha256": row["sha256"]} for row in items],
        "audit": {
            "count": len(events),
            "first_event_id": events[0]["event_id"] if events else None,
            "last_event_id": events[-1]["event_id"] if events else None,
            "previous_hash": events[0]["previous_hash"] if events else None,
            "head_hash": events[-1]["event_hash"] if events else None,
        },
    }
    connection.execute(
        "UPDATE evidence_tasks SET state='completed', manifest_json=?, package_sha256=?, finished_at=? "
        "WHERE task_id=?",
        (canonical_json(manifest), digest(manifest), now, task["task_id"]),
    )


def run_task(
    connection: sqlite3.Connection,
    clock: Any,
    task_id: str,
    *,
    max_steps: int | None = None,
) -> dict[str, Any]:
    """执行证据任务步骤；每步单独提交，中断后可从游标续作。"""
    if max_steps is not None and max_steps <= 0:
        raise ValidationFailed("max_steps 必须是正整数")
    row = connection.execute("SELECT * FROM evidence_tasks WHERE task_id=?", (task_id,)).fetchone()
    if row is None:
        raise NotFound("证据任务不存在")
    task = dict(row)
    if task["state"] == "completed":
        return task_status(connection, task_id)
    plan = list(STEP_PLANS[task["root_type"]]) + ["finalize"]
    snapshot = json.loads(task["snapshot_json"])
    now = utc_text(clock.now())
    if task["state"] in ("pending", "failed"):
        with transaction(connection, immediate=True):
            connection.execute(
                "UPDATE evidence_tasks SET state='running', started_at=COALESCE(started_at,?), error=NULL "
                "WHERE task_id=?",
                (now, task_id),
            )
    cursor = int(task["cursor"])
    executed = 0
    while cursor < len(plan) and (max_steps is None or executed < max_steps):
        step = plan[cursor]
        try:
            with transaction(connection, immediate=True):
                if step == "finalize":
                    _finalize(connection, task, snapshot, now)
                else:
                    handler = _STEP_HANDLERS[(task["root_type"], step)]
                    handler(connection, task, snapshot)
                connection.execute(
                    "UPDATE evidence_tasks SET cursor=? WHERE task_id=?", (cursor + 1, task_id)
                )
        except Exception as exc:
            with transaction(connection, immediate=True):
                connection.execute(
                    "UPDATE evidence_tasks SET state='failed', error=? WHERE task_id=?",
                    (f"{type(exc).__name__}: {exc}"[:500], task_id),
                )
            break
        cursor += 1
        executed += 1
    return task_status(connection, task_id)


def run_pending(
    connection: sqlite3.Connection,
    clock: Any,
    *,
    max_tasks: int | None = None,
    max_steps: int | None = None,
) -> list[dict[str, Any]]:
    """按创建顺序执行待处理与被中断的证据任务。"""
    rows = connection.execute(
        "SELECT task_id FROM evidence_tasks WHERE state IN ('pending','running') ORDER BY created_at, task_id"
    ).fetchall()
    if max_tasks is not None:
        rows = rows[:max_tasks]
    return [run_task(connection, clock, row["task_id"], max_steps=max_steps) for row in rows]


def export_package(connection: sqlite3.Connection, task_id: str) -> dict[str, Any]:
    """导出可离线复核的完整证据包。"""
    row = connection.execute("SELECT * FROM evidence_tasks WHERE task_id=?", (task_id,)).fetchone()
    if row is None:
        raise NotFound("证据任务不存在")
    if row["state"] != "completed":
        raise InvalidState("证据任务尚未完成")
    items = connection.execute(
        "SELECT item_key,item_type,content_json,sha256 FROM evidence_items WHERE task_id=? ORDER BY item_key",
        (task_id,),
    ).fetchall()
    return {
        "format": FORMAT,
        "manifest": json.loads(row["manifest_json"]),
        "items": [
            {
                "key": item["item_key"],
                "type": item["item_type"],
                "sha256": item["sha256"],
                "content": json.loads(item["content_json"]),
            }
            for item in items
        ],
        "package_sha256": row["package_sha256"],
    }


def _audit_body(source: Mapping[str, Any]) -> dict[str, Any]:
    payload = source.get("payload")
    if payload is None:
        payload = json.loads(source["payload_json"])
    return {
        "entity_type": source["entity_type"],
        "entity_id": source["entity_id"],
        "event_type": source["event_type"],
        "actor_id": source["actor_id"],
        "payload": payload,
        "created_at": source["created_at"],
        "previous_hash": source["previous_hash"],
    }


def _verify_reference(
    connection: sqlite3.Connection,
    redaction: str,
    item: Mapping[str, Any],
    report: dict[str, Any],
) -> None:
    item_type = item["type"]
    key = item["key"]
    content = item["content"]
    reference = REFERENCES.get(item_type)
    if reference is None:
        report["structure_errors"].append(f"未知证据类型: {item_type}")
        return
    table, field = reference
    primary_key = content.get(field)
    if primary_key is None:
        report["structure_errors"].append(f"证据 {key} 缺少主键字段 {field}")
        return
    row = connection.execute(f"SELECT * FROM {table} WHERE {field}=?", (primary_key,)).fetchone()
    if row is None:
        report["missing_references"].append({"item": key, "type": item_type, "id": primary_key})
        return
    if digest(project_item(item_type, row, redaction)) != digest(content):
        report["digest_mismatches"].append({"item": key, "detail": "数据库当前投影与证据内容不符"})


def _verify_audit_fragment(
    connection: sqlite3.Connection,
    manifest: Mapping[str, Any],
    audit_items: list[Mapping[str, Any]],
    report: dict[str, Any],
) -> None:
    if not audit_items:
        return
    events = sorted(audit_items, key=lambda content: content.get("event_id", 0))
    summary = manifest.get("audit")
    if not isinstance(summary, Mapping) or (
        summary.get("count") != len(events)
        or summary.get("head_hash") != events[-1].get("event_hash")
        or summary.get("previous_hash") != events[0].get("previous_hash")
    ):
        report["audit_chain_breaks"].append({"detail": "清单审计摘要与证据事件不符"})
    event_ids = [event.get("event_id") for event in events]
    if not all(isinstance(event_id, int) for event_id in event_ids):
        report["audit_chain_breaks"].append({"detail": "审计事件编号缺失或不是整数"})
        return
    rows = connection.execute(
        "SELECT * FROM supply_audit_events WHERE event_id<=? ORDER BY event_id", (max(event_ids),)
    ).fetchall()
    computed: dict[int, str] = {}
    previous = "0" * 64
    broken = None
    for row in rows:
        event_hash = digest(_audit_body(dict(row)))
        if row["previous_hash"] != previous or row["event_hash"] != event_hash:
            broken = row["event_id"]
            break
        computed[row["event_id"]] = event_hash
        previous = event_hash
    if broken is not None:
        report["audit_chain_breaks"].append({"detail": "数据库审计链断裂", "event_id": broken})
    for event in events:
        event_id = event["event_id"]
        if digest(_audit_body(event)) != event.get("event_hash"):
            report["audit_chain_breaks"].append({"event_id": event_id, "detail": "事件内容与事件摘要不符"})
        row = connection.execute(
            "SELECT previous_hash,event_hash FROM supply_audit_events WHERE event_id=?", (event_id,)
        ).fetchone()
        if row is None:
            continue
        if row["event_hash"] != event.get("event_hash") or row["previous_hash"] != event.get("previous_hash"):
            report["audit_chain_breaks"].append({"event_id": event_id, "detail": "事件摘要与数据库记录不符"})
        if event_id == 1:
            expected_previous = "0" * 64
        elif event_id - 1 in computed:
            expected_previous = computed[event_id - 1]
        else:
            continue
        if event.get("previous_hash") != expected_previous:
            report["audit_chain_breaks"].append({"event_id": event_id, "detail": "事件前向链接与审计链不符"})


def verify_package(connection: sqlite3.Connection, package: object) -> dict[str, Any]:
    """验证证据包，分别报告缺失引用、摘要不符与审计断链。"""
    report: dict[str, Any] = {
        "valid": False,
        "checked_items": 0,
        "structure_errors": [],
        "missing_references": [],
        "digest_mismatches": [],
        "audit_chain_breaks": [],
    }
    if not isinstance(package, Mapping):
        report["structure_errors"].append("证据包必须是 JSON 对象")
        report["valid"] = False
        return report
    manifest = package.get("manifest")
    items = package.get("items")
    declared = package.get("package_sha256")
    if package.get("format") != FORMAT:
        report["structure_errors"].append("证据包格式版本不受支持")
    if not isinstance(manifest, Mapping) or not isinstance(items, list) or not isinstance(declared, str):
        report["structure_errors"].append("证据包缺少 manifest、items 或 package_sha256")
        return report
    if manifest.get("format") != FORMAT:
        report["structure_errors"].append("清单格式版本不受支持")
    redaction = manifest.get("redaction", "masked")
    actual = digest(manifest)
    if actual != declared:
        report["digest_mismatches"].append({"scope": "package", "declared": declared, "actual": actual})
    manifest_entries: dict[str, Mapping[str, Any]] = {}
    for entry in manifest.get("items", []):
        if isinstance(entry, Mapping) and isinstance(entry.get("key"), str):
            manifest_entries[entry["key"]] = entry
    seen: set[str] = set()
    audit_items: list[Mapping[str, Any]] = []
    for item in items:
        if not isinstance(item, Mapping) or not all(field in item for field in ("key", "type", "content")):
            report["structure_errors"].append("证据条目缺少 key、type 或 content")
            continue
        key = item["key"]
        content = item["content"]
        seen.add(key)
        if not isinstance(content, Mapping):
            report["structure_errors"].append(f"证据条目 {key} 的内容不是对象")
            continue
        recomputed = digest(content)
        if item.get("sha256") != recomputed:
            report["digest_mismatches"].append(
                {"item": key, "detail": "条目摘要与内容不符", "declared": item.get("sha256"), "actual": recomputed}
            )
        entry = manifest_entries.get(key)
        if entry is None:
            report["structure_errors"].append(f"证据条目 {key} 未在清单中声明")
        elif entry.get("sha256") != recomputed:
            report["digest_mismatches"].append(
                {"item": key, "detail": "清单摘要与内容不符", "declared": entry.get("sha256"), "actual": recomputed}
            )
        if item["type"] == "audit_event":
            audit_items.append(content)
        _verify_reference(connection, redaction, item, report)
    for key in sorted(set(manifest_entries) - seen):
        report["structure_errors"].append(f"清单声明的 {key} 缺少证据内容")
    _verify_audit_fragment(connection, manifest, audit_items, report)
    task_row = connection.execute(
        "SELECT state,package_sha256 FROM evidence_tasks WHERE task_id=?", (manifest.get("task_id"),)
    ).fetchone()
    if task_row is not None and task_row["state"] == "completed" and task_row["package_sha256"] != declared:
        report["digest_mismatches"].append(
            {"scope": "task", "detail": "包摘要与数据库任务记录不符",
             "declared": declared, "actual": task_row["package_sha256"]}
        )
    report["checked_items"] = len(items)
    report["valid"] = not (
        report["structure_errors"]
        or report["missing_references"]
        or report["digest_mismatches"]
        or report["audit_chain_breaks"]
    )
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="油气供应审计证据包收集与验证工具")
    parser.add_argument("--database", type=Path, required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    request = commands.add_parser("request", help="申请证据任务")
    request.add_argument("--actor", required=True)
    request.add_argument("--root-type", required=True, choices=ROOT_TYPES)
    request.add_argument("--root-id", required=True)
    run = commands.add_parser("run", help="执行待处理或指定证据任务")
    run.add_argument("--task")
    run.add_argument("--max-steps", type=int)
    status = commands.add_parser("status", help="查看证据任务状态")
    status.add_argument("--task", required=True)
    export = commands.add_parser("export", help="导出证据包 JSON")
    export.add_argument("--task", required=True)
    verify = commands.add_parser("verify", help="验证证据包 JSON 文件")
    verify.add_argument("--package", type=Path, required=True)
    args = parser.parse_args(argv)
    connection = connect(args.database)
    try:
        clock = SystemClock()
        if args.command == "request":
            from .service import SupplyService

            result = SupplyService(connection, clock).request_evidence_task(
                args.actor, args.root_type, args.root_id
            )
            print(json.dumps(result, ensure_ascii=False, sort_keys=True))
            return 0
        if args.command == "run":
            if args.task:
                result: object = run_task(connection, clock, args.task, max_steps=args.max_steps)
            else:
                result = {"tasks": run_pending(connection, clock, max_steps=args.max_steps)}
            print(json.dumps(result, ensure_ascii=False, sort_keys=True))
            return 0
        if args.command == "status":
            print(json.dumps(task_status(connection, args.task), ensure_ascii=False, sort_keys=True))
            return 0
        if args.command == "export":
            print(json.dumps(export_package(connection, args.task), ensure_ascii=False, sort_keys=True))
            return 0
        package = json.loads(args.package.read_text(encoding="utf-8"))
        report = verify_package(connection, package)
        print(json.dumps(report, ensure_ascii=False, sort_keys=True))
        return 0 if report["valid"] else 1
    except SupplyError as exc:
        print(json.dumps({"error": {"code": exc.code, "message": str(exc)}}, ensure_ascii=False))
        return 2
    finally:
        connection.close()


if __name__ == "__main__":
    raise SystemExit(main())
