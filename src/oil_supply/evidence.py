"""可离线复核、防篡改的调度决定审计证据包。

审计员选定一个根对象（分配运行、转运或情景结果），证据任务沿数据库中的
真实外键与审计事件引用收集报价修订、设施与线路版本、停运记录、库存批次、
提名/转运等操作决定以及对应的哈希链审计片段。

关键边界：

- 每个根对象以其登记审计事件作为锚点（cutoff），锚点之后的写入绝不进入包，
  因此任务启动后的新数据不可能混入，同一根版本重复申请得到同一摘要；
- 任务与条目持久化在 ``evidence_jobs`` / ``evidence_items`` 中，逐条提交，
  中断后再次运行即可续作；
- 用户资料按审计权限脱敏：仅保留 user_id 与角色，display_name 不出包；
- 清单与整包均使用 :func:`oil_supply.planning.canonical_json` 规范化并计算
  SHA-256，验证时把缺失引用、摘要不符、审计断链三类问题分别报告。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import threading
from decimal import Decimal
from pathlib import Path
from typing import Any, Mapping, Sequence

from .clock import utc_text
from .errors import Forbidden, InvalidState, NotFound, SupplyError, ValidationFailed
from .planning import canonical_json
from .service import ROLE_PERMISSIONS
from .storage import connect, transaction

PACKAGE_FORMAT = "oil-supply-evidence/1"
MANIFEST_FORMAT = "oil-supply-evidence-manifest/1"
ZERO_HASH = "0" * 64

ROOT_KINDS = ("allocation", "transfer", "scenario_run")
ROOT_TABLES = {
    "allocation": ("allocation_runs", "allocation_id"),
    "transfer": ("transfers", "transfer_id"),
    "scenario_run": ("scenario_runs", "run_id"),
}
ROOT_ANCHOR_EVENTS = {
    "allocation": ("route", "allocation.completed", "allocation_id"),
    "transfer": ("transfer", "transfer.dispatched", None),
    "scenario_run": ("scenario", "scenario.executed", "run_id"),
}


def _allocation_entries(result_json: str) -> list[dict[str, Any]]:
    parsed = json.loads(result_json)
    return list(parsed["allocations"])

# 验证结论的三个独立类别。
MISSING_REFERENCE = "missing_reference"
DIGEST_MISMATCH = "digest_mismatch"
AUDIT_CHAIN = "audit_chain"


def _ref_id(root_kind: str, ref: Mapping[str, Any]) -> object:
    if root_kind == "allocation":
        return int(ref["allocation_id"])
    if root_kind == "transfer":
        return str(ref["transfer_id"])
    return int(ref["run_id"])


def _item_sha256(item: Mapping[str, Any]) -> str:
    body = {key: value for key, value in item.items() if key != "sha256"}
    return hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()


def _package_sha256(package: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json(package).encode("utf-8")).hexdigest()


def _actor(user_roles: Mapping[str, str | None], user_id: str | None) -> dict[str, Any]:
    return {
        "user_id": user_id,
        "role": None if user_id is None else user_roles.get(user_id),
        "display_name": None,
    }


def _event_body(row: sqlite3.Row, user_roles: Mapping[str, str | None]) -> dict[str, Any]:
    return {
        "event_id": row["event_id"],
        "entity_type": row["entity_type"],
        "entity_id": row["entity_id"],
        "event_type": row["event_type"],
        "actor": _actor(user_roles, row["actor_id"]),
        "payload": json.loads(row["payload_json"]),
        "created_at": row["created_at"],
        "previous_hash": row["previous_hash"],
        "event_hash": row["event_hash"],
    }


def _recomputed_event_hash(event: Mapping[str, Any]) -> str:
    body = {
        "entity_type": event["entity_type"],
        "entity_id": event["entity_id"],
        "event_type": event["event_type"],
        "actor_id": event["actor"]["user_id"],
        "payload": event["payload"],
        "created_at": event["created_at"],
        "previous_hash": event["previous_hash"],
    }
    return hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()


class _Anchor:
    __slots__ = ("event_id", "event_hash", "at")

    def __init__(self, event_id: int, event_hash: str, at: str) -> None:
        self.event_id = event_id
        self.event_hash = event_hash
        self.at = at


class _Context:
    """一次证据收集的固定视图：锚点、用户角色与锚点前事件索引。

    业务表自身不带审计序号，时间戳在同一秒内无法区分先后，因此围栏一律用
    审计事件 ID（锚点事件 ID 及之前才可见），而不是用 created_at 比较。
    """

    def __init__(self, connection: sqlite3.Connection, anchor: _Anchor) -> None:
        self.connection = connection
        self.anchor = anchor
        rows = connection.execute(
            "SELECT * FROM supply_audit_events WHERE event_id<=? ORDER BY event_id",
            (anchor.event_id,),
        ).fetchall()
        self.events = {row["event_id"]: row for row in rows}
        user_rows = connection.execute("SELECT user_id,role FROM supply_users").fetchall()
        self.user_roles: dict[str, str] = {row["user_id"]: row["role"] for row in user_rows}
        self.birth_events: dict[tuple[str, str], int] = {}
        for row in rows:
            self._index_birth(row)

    def _index_birth(self, row: sqlite3.Row) -> None:
        entity_type, entity_id = row["entity_type"], row["entity_id"]
        event_type = row["event_type"]
        mapping = {
            "facility.created": ("facility", entity_id),
            "route.created": ("route", entity_id),
            "quote.recorded": ("quote", entity_id),
            "inventory.received": ("lot", entity_id),
            "nomination.submitted": ("nomination", entity_id),
            "transfer.dispatched": ("transfer", entity_id),
            "scenario.created": ("scenario", entity_id),
        }.get(event_type)
        if mapping is not None:
            self.birth_events.setdefault(mapping, row["event_id"])
        try:
            payload = json.loads(row["payload_json"])
        except ValueError:
            return
        if event_type == "outage.announced" and "outage_id" in payload:
            self.birth_events.setdefault(("outage", str(payload["outage_id"])), row["event_id"])
        if event_type == "allocation.completed" and "allocation_id" in payload:
            self.birth_events.setdefault(("allocation", str(payload["allocation_id"])), row["event_id"])
        if event_type == "scenario.executed" and "run_id" in payload:
            self.birth_events.setdefault(("scenario_run", str(payload["run_id"])), row["event_id"])

    def visible(self, kind: str, key: object) -> bool:
        """该业务行的登记事件是否在锚点（含）之前。"""
        event_id = self.birth_events.get((kind, str(key)))
        return event_id is not None and event_id <= self.anchor.event_id

    def event_for(
        self, entity_type: str, entity_id: str, event_type: str, payload_key: str | None, payload_value: object
    ) -> sqlite3.Row | None:
        for row in self.events.values():
            if (
                row["entity_type"] == entity_type
                and row["entity_id"] == str(entity_id)
                and row["event_type"] == event_type
            ):
                if payload_key is None:
                    return row
                try:
                    payload = json.loads(row["payload_json"])
                except ValueError:
                    continue
                if payload.get(payload_key) == payload_value:
                    return row
        return None


class EvidenceService:
    def __init__(self, connection: sqlite3.Connection, clock=None) -> None:
        self.connection = connection
        from .clock import SystemClock
        from .storage import initialize

        self.clock = clock or SystemClock()
        initialize(connection)
        self._running: set[str] = set()
        self._running_lock = threading.Lock()
        self._db_lock = threading.RLock()

    # ------------------------------------------------------------------ 权限

    def require_audit(self, actor_id: str) -> None:
        self._require(actor_id, "audit.read")

    def _require(self, actor_id: str, permission: str) -> None:
        row = self.connection.execute(
            "SELECT * FROM supply_users WHERE user_id=?", (actor_id,)
        ).fetchone()
        if row is None:
            raise NotFound("用户不存在")
        if not row["active"]:
            raise Forbidden("用户已停用")
        if permission not in ROLE_PERMISSIONS[row["role"]]:
            raise Forbidden(f"角色 {row['role']} 无权执行 {permission}")

    def _now(self) -> str:
        return utc_text(self.clock.now())

    # -------------------------------------------------------------- 建任务

    def request_package(self, actor_id: str, root_kind: str, ref: Mapping[str, Any]) -> dict[str, Any]:
        self._require(actor_id, "audit.read")
        if root_kind not in ROOT_KINDS:
            raise ValidationFailed("root_kind 必须是 allocation、transfer 或 scenario_run")
        root_id = _ref_id(root_kind, ref)
        table, column = ROOT_TABLES[root_kind]
        root_row = self.connection.execute(
            f"SELECT * FROM {table} WHERE {column}=?", (root_id,)
        ).fetchone()
        if root_row is None:
            raise NotFound("根对象不存在")
        fence = self.connection.execute(
            "SELECT max(event_id) AS event_id FROM supply_audit_events"
        ).fetchone()["event_id"]
        if fence is None:
            raise InvalidState("审计链为空，无法为根对象定位锚点事件")
        anchor_row = self._anchor_event(root_kind, root_id, fence)
        if anchor_row is None:
            raise InvalidState("根对象缺少对应的审计锚点事件")
        anchor = _Anchor(anchor_row["event_id"], anchor_row["event_hash"], anchor_row["created_at"])
        job_id = f"ev-{root_kind.replace('_', '-')}-{root_id}"
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO evidence_jobs(job_id,root_kind,root_ref,cutoff_event_id,cutoff_head_hash,"
                    "cutoff_at,state,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (
                        job_id,
                        root_kind,
                        canonical_json(ref),
                        anchor.event_id,
                        anchor.event_hash,
                        anchor.at,
                        "pending",
                        actor_id,
                        self._now(),
                        self._now(),
                    ),
                )
        except sqlite3.IntegrityError:
            existing = self.get_job(job_id=job_id)
            existing["reused"] = True
            return existing
        return {"job_id": job_id, "state": "pending", "reused": False}

    def _anchor_event(self, root_kind: str, root_id: object, fence: int) -> sqlite3.Row | None:
        entity_type, event_type, payload_key = ROOT_ANCHOR_EVENTS[root_kind]
        rows = self.connection.execute(
            "SELECT * FROM supply_audit_events WHERE event_type=? AND event_id<=? ORDER BY event_id",
            (event_type, fence),
        ).fetchall()
        for row in rows:
            if root_kind == "transfer":
                if row["entity_type"] == "transfer" and row["entity_id"] == str(root_id):
                    return row
                continue
            try:
                payload = json.loads(row["payload_json"])
            except ValueError:
                continue
            if payload.get(payload_key) == root_id:
                return row
        return None

    # -------------------------------------------------------------- 执行任务

    def advance_job(self, job_id: str) -> dict[str, Any]:
        with self._db_lock:
            return self._advance_job_locked(job_id)

    def _advance_job_locked(self, job_id: str) -> dict[str, Any]:
        job = self._job_row(job_id)
        if job["state"] == "ready":
            return self.get_job(job_id)
        with transaction(self.connection, immediate=True):
            self.connection.execute(
                "UPDATE evidence_jobs SET state='collecting',updated_at=? WHERE job_id=? AND state!='ready'",
                (self._now(), job_id),
            )
        try:
            anchor = _Anchor(job["cutoff_event_id"], job["cutoff_head_hash"], job["cutoff_at"])
            ctx = _Context(self.connection, anchor)
            root_ref = json.loads(job["root_ref"])
            planned = self._plan(job["root_kind"], root_ref, ctx)
            self._store_plan(job_id, planned)
            for descriptor in planned:
                self._collect_item(job_id, descriptor, ctx)
            package, manifest = self._assemble(job_id, job, ctx, root_ref)
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "UPDATE evidence_jobs SET state='ready',manifest_json=?,package_json=?,package_sha256=?,"
                    "error_text=NULL,updated_at=? WHERE job_id=?",
                    (
                        canonical_json(manifest),
                        canonical_json(package),
                        manifest["package_sha256"],
                        self._now(),
                        job_id,
                    ),
                )
        except Exception as exc:  # 任务失败可重试，不影响其它任务
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "UPDATE evidence_jobs SET state='failed',error_text=?,updated_at=? WHERE job_id=?",
                    (str(exc), self._now(), job_id),
                )
            raise
        return self.get_job(job_id)

    def start_background(self, job_id: str) -> None:
        with self._running_lock:
            if job_id in self._running:
                return
            self._running.add(job_id)

        def worker() -> None:
            try:
                self.advance_job(job_id)
            except Exception:
                pass
            finally:
                with self._running_lock:
                    self._running.discard(job_id)

        thread = threading.Thread(target=worker, name=f"evidence-{job_id}", daemon=True)
        thread.start()

    def _job_row(self, job_id: str) -> sqlite3.Row:
        row = self.connection.execute("SELECT * FROM evidence_jobs WHERE job_id=?", (job_id,)).fetchone()
        if row is None:
            raise NotFound("证据任务不存在")
        return row

    # ------------------------------------------------------------------ 规划

    def _store_plan(self, job_id: str, planned: Sequence[Mapping[str, Any]]) -> None:
        with transaction(self.connection, immediate=True):
            for ordinal, descriptor in enumerate(planned):
                self.connection.execute(
                    "INSERT OR IGNORE INTO evidence_items(job_id,item_id,item_kind,ref_json,anchor_at,ordinal)"
                    " VALUES(?,?,?,?,?,?)",
                    (
                        job_id,
                        descriptor["item_id"],
                        descriptor["kind"],
                        canonical_json(descriptor["ref"]),
                        descriptor.get("anchor_at"),
                        ordinal,
                    ),
                )

    def _add(self, planned: list[dict[str, Any]], kind: str, ref: Mapping[str, Any], anchor_at: str | None = None) -> None:
        item_id = f"{kind}:" + ":".join(str(value) for value in ref.values())
        for existing in planned:
            if existing["item_id"] == item_id:
                return
        planned.append({"item_id": item_id, "kind": kind, "ref": dict(ref), "anchor_at": anchor_at})

    def _plan(self, root_kind: str, root_ref: Mapping[str, Any], ctx: _Context) -> list[dict[str, Any]]:
        planned: list[dict[str, Any]] = []
        if root_kind == "allocation":
            self._plan_allocation(planned, int(root_ref["allocation_id"]), ctx)
        elif root_kind == "transfer":
            self._plan_transfer(planned, str(root_ref["transfer_id"]), ctx)
        else:
            self._plan_scenario_run(planned, int(root_ref["run_id"]), ctx)
        planned.sort(key=lambda item: item["item_id"])
        return planned

    def _plan_route_closure(self, planned: list[dict[str, Any]], route_id: str, ctx: _Context) -> None:
        route = ctx.connection.execute("SELECT * FROM routes WHERE route_id=?", (route_id,)).fetchone()
        if route is None:
            self._add(planned, "route", {"route_id": route_id})
            return
        self._add(planned, "route", {"route_id": route_id}, route["created_at"])
        self._add(planned, "facility", {"facility_id": route["origin_id"]})
        self._add(planned, "facility", {"facility_id": route["destination_id"]})
        for outage in self._outages_in_window(route_id, ctx):
            self._add(planned, "outage", {"outage_id": int(outage["outage_id"])}, outage["created_at"])

    def _outages_in_window(self, route_id: str, ctx: _Context) -> list[sqlite3.Row]:
        rows = ctx.connection.execute(
            "SELECT * FROM route_outages WHERE route_id=? ORDER BY outage_id",
            (route_id,),
        ).fetchall()
        return [row for row in rows if ctx.visible("outage", row["outage_id"])]

    def _plan_allocation(self, planned: list[dict[str, Any]], allocation_id: int, ctx: _Context) -> None:
        row = ctx.connection.execute(
            "SELECT * FROM allocation_runs WHERE allocation_id=?", (allocation_id,)
        ).fetchone()
        self._add(planned, "allocation", {"allocation_id": allocation_id})
        if row is None:
            return
        self._plan_route_closure(planned, row["route_id"], ctx)
        for entry in _allocation_entries(row["result_json"]):
            self._add(planned, "nomination", {"nomination_id": entry["nomination_id"]})

    def _plan_transfer(self, planned: list[dict[str, Any]], transfer_id: str, ctx: _Context) -> None:
        self._add(planned, "transfer", {"transfer_id": transfer_id})
        root_row = ctx.connection.execute(
            "SELECT * FROM transfers WHERE transfer_id=?", (transfer_id,)
        ).fetchone()
        if root_row is None:
            return
        self._add(planned, "lot", {"lot_id": root_row["inventory_lot_id"]})
        # 锚点前消耗同一批次的所有转运共同决定批次在锚点的可用数量版本，
        # 因此每个转运都要带上自己的提名与所属分配运行。
        lot_transfers = [
            row
            for row in ctx.connection.execute(
                "SELECT transfer_id,nomination_id,inventory_lot_id FROM transfers "
                "WHERE inventory_lot_id=? ORDER BY departed_at,transfer_id",
                (root_row["inventory_lot_id"],),
            ).fetchall()
            if ctx.visible("transfer", row["transfer_id"])
        ]
        route_ids: set[str] = set()
        for transfer in lot_transfers:
            self._add(planned, "transfer", {"transfer_id": transfer["transfer_id"]})
            nomination = ctx.connection.execute(
                "SELECT * FROM nominations WHERE nomination_id=?", (transfer["nomination_id"],)
            ).fetchone()
            if nomination is None:
                self._add(planned, "nomination", {"nomination_id": transfer["nomination_id"]})
                continue
            self._add(planned, "nomination", {"nomination_id": nomination["nomination_id"]})
            if nomination["route_id"] not in route_ids:
                route_ids.add(nomination["route_id"])
                self._plan_route_closure(planned, nomination["route_id"], ctx)
            allocation = self._allocation_for(nomination["route_id"], nomination["nomination_id"], ctx)
            if allocation is not None:
                self._add(
                    planned,
                    "allocation",
                    {"allocation_id": int(allocation["allocation_id"])},
                    allocation["created_at"],
                )
                for entry in _allocation_entries(allocation["result_json"]):
                    self._add(planned, "nomination", {"nomination_id": entry["nomination_id"]})

    def _allocation_for(self, route_id: str, nomination_id: str, ctx: _Context) -> sqlite3.Row | None:
        rows = ctx.connection.execute(
            "SELECT * FROM allocation_runs WHERE route_id=? ORDER BY allocation_id DESC",
            (route_id,),
        ).fetchall()
        for row in rows:
            if not ctx.visible("allocation", row["allocation_id"]):
                continue
            entries = _allocation_entries(row["result_json"])
            if any(entry["nomination_id"] == nomination_id for entry in entries):
                return row
        return None

    def _plan_scenario_run(self, planned: list[dict[str, Any]], run_id: int, ctx: _Context) -> None:
        self._add(planned, "scenario_run", {"run_id": run_id})
        row = ctx.connection.execute("SELECT * FROM scenario_runs WHERE run_id=?", (run_id,)).fetchone()
        if row is None:
            return
        self._add(planned, "scenario", {"scenario_id": row["scenario_id"]})
        quote_rows = ctx.connection.execute(
            "SELECT * FROM price_index_quotes WHERE trade_date<=? ORDER BY trade_date DESC,quote_id DESC",
            (row["as_of_date"],),
        ).fetchall()
        effective = next((candidate for candidate in quote_rows if ctx.visible("quote", candidate["quote_id"])), None)
        if effective is not None:
            cursor = effective
            while cursor is not None:
                self._add(planned, "quote", {"quote_id": int(cursor["quote_id"])}, cursor["recorded_at"])
                if cursor["supersedes_quote_id"] is None:
                    break
                cursor = ctx.connection.execute(
                    "SELECT * FROM price_index_quotes WHERE quote_id=?",
                    (cursor["supersedes_quote_id"],),
                ).fetchone()
        for route in ctx.connection.execute("SELECT route_id FROM routes ORDER BY route_id").fetchall():
            if ctx.visible("route", route["route_id"]):
                self._plan_route_closure(planned, route["route_id"], ctx)
        for lot in ctx.connection.execute("SELECT lot_id FROM inventory_lots ORDER BY lot_id").fetchall():
            if ctx.visible("lot", lot["lot_id"]):
                self._add(planned, "lot", {"lot_id": lot["lot_id"]})
        for transfer in ctx.connection.execute("SELECT transfer_id FROM transfers ORDER BY transfer_id").fetchall():
            if ctx.visible("transfer", transfer["transfer_id"]):
                self._plan_transfer(planned, transfer["transfer_id"], ctx)

    # ---------------------------------------------------------------- 收集

    def _collect_item(self, job_id: str, descriptor: Mapping[str, Any], ctx: _Context) -> None:
        row = ctx.connection.execute(
            "SELECT status FROM evidence_items WHERE job_id=? AND item_id=?",
            (job_id, descriptor["item_id"]),
        ).fetchone()
        if row is not None and row["status"] in ("collected", "missing"):
            return
        kind = descriptor["kind"]
        try:
            content, evidence_ids = self._build_content(kind, descriptor["ref"], ctx)
            status = "collected"
            content_json = canonical_json(content)
            reason = None
        except _MissingReference as missing:
            status = "missing"
            content_json = None
            evidence_ids = []
            reason = str(missing)
        evidence_ids = sorted(set(evidence_ids))
        item = {
            "item_id": descriptor["item_id"],
            "kind": kind,
            "ref": descriptor["ref"],
            "status": status,
            "anchor_at": descriptor.get("anchor_at"),
            "content": None if content_json is None else json.loads(content_json),
            "missing_reason": reason,
            "evidence_event_ids": evidence_ids,
        }
        item["sha256"] = _item_sha256(item)
        with transaction(self.connection, immediate=True):
            self.connection.execute(
                "UPDATE evidence_items SET status=?,detail_text=?,content_json=?,item_sha256=?,"
                "evidence_event_ids_json=?,anchor_at=? WHERE job_id=? AND item_id=?",
                (
                    status,
                    reason,
                    None if content_json is None else content_json,
                    item["sha256"],
                    canonical_json(evidence_ids),
                    descriptor.get("anchor_at"),
                    job_id,
                    descriptor["item_id"],
                ),
            )

    def _build_content(
        self, kind: str, ref: Mapping[str, Any], ctx: _Context
    ) -> tuple[dict[str, Any], list[int]]:
        builder = {
            "allocation": self._content_allocation,
            "transfer": self._content_transfer,
            "scenario_run": self._content_scenario_run,
            "scenario": self._content_scenario,
            "route": self._content_route,
            "facility": self._content_facility,
            "outage": self._content_outage,
            "quote": self._content_quote,
            "lot": self._content_lot,
            "nomination": self._content_nomination,
        }[kind]
        return builder(ref, ctx)

    @staticmethod
    def _require_row(row: sqlite3.Row | None, label: str) -> sqlite3.Row:
        if row is None:
            raise _MissingReference(label)
        return row

    def _content_route(self, ref: Mapping[str, Any], ctx: _Context) -> tuple[dict[str, Any], list[int]]:
        row = self._require_row(
            ctx.connection.execute("SELECT * FROM routes WHERE route_id=?", (ref["route_id"],)).fetchone(),
            f"线路 {ref['route_id']} 不存在",
        )
        event = ctx.event_for("route", row["route_id"], "route.created", None, None)
        missing: list[dict[str, Any]] = []
        evidence: list[int] = []
        registration = None
        if event is None or event["event_id"] > ctx.anchor.event_id:
            missing.append({"entity_type": "route", "entity_id": row["route_id"], "event_type": "route.created"})
        else:
            registration = json.loads(event["payload_json"])
            evidence.append(event["event_id"])
        content = {
            "route_id": row["route_id"],
            "origin_id": row["origin_id"],
            "destination_id": row["destination_id"],
            "product": row["product"],
            "daily_capacity": row["daily_capacity"],
            "loss_basis_points": row["loss_basis_points"],
            "transit_hours": row["transit_hours"],
            "revision": row["revision"],
            "state_at_anchor": "active" if ctx.visible("route", row["route_id"]) else None,
            "registration": registration,
            "recorded_at": row["created_at"],
            "missing_events": missing,
        }
        return content, evidence

    def _content_facility(self, ref: Mapping[str, Any], ctx: _Context) -> tuple[dict[str, Any], list[int]]:
        row = self._require_row(
            ctx.connection.execute("SELECT * FROM facilities WHERE facility_id=?", (ref["facility_id"],)).fetchone(),
            f"设施 {ref['facility_id']} 不存在",
        )
        event = ctx.event_for("facility", row["facility_id"], "facility.created", None, None)
        missing: list[dict[str, Any]] = []
        evidence: list[int] = []
        registration = None
        if event is None or event["event_id"] > ctx.anchor.event_id:
            missing.append({"entity_type": "facility", "entity_id": row["facility_id"], "event_type": "facility.created"})
        else:
            registration = json.loads(event["payload_json"])
            evidence.append(event["event_id"])
        content = {
            "facility_id": row["facility_id"],
            "name": row["name"],
            "kind": row["kind"],
            "timezone": row["timezone"],
            "capacity_barrels": row["capacity_barrels"],
            "registration": registration,
            "recorded_at": row["created_at"],
            "missing_events": missing,
        }
        return content, evidence

    def _content_outage(self, ref: Mapping[str, Any], ctx: _Context) -> tuple[dict[str, Any], list[int]]:
        row = self._require_row(
            ctx.connection.execute("SELECT * FROM route_outages WHERE outage_id=?", (ref["outage_id"],)).fetchone(),
            f"停运记录 {ref['outage_id']} 不存在",
        )
        event = ctx.event_for("route", row["route_id"], "outage.announced", "outage_id", int(row["outage_id"]))
        evidence: list[int] = []
        missing: list[dict[str, Any]] = []
        if event is None or event["event_id"] > ctx.anchor.event_id:
            missing.append({"entity_type": "route", "entity_id": row["route_id"], "event_type": "outage.announced", "outage_id": int(row["outage_id"])})
        else:
            evidence.append(event["event_id"])
        content = {
            "outage_id": int(row["outage_id"]),
            "route_id": row["route_id"],
            "starts_at": row["starts_at"],
            "ends_at": row["ends_at"],
            "capacity_percent": row["capacity_percent"],
            "reason": row["reason"],
            "state_recorded": row["state"],
            "revision": row["revision"],
            "announced_by": _actor(ctx.user_roles, row["created_by"]),
            "announced_at": row["created_at"],
            "missing_events": missing,
        }
        return content, evidence

    def _content_quote(self, ref: Mapping[str, Any], ctx: _Context) -> tuple[dict[str, Any], list[int]]:
        row = self._require_row(
            ctx.connection.execute("SELECT * FROM price_index_quotes WHERE quote_id=?", (ref["quote_id"],)).fetchone(),
            f"报价 {ref['quote_id']} 不存在",
        )
        event = ctx.event_for("quote", row["quote_id"], "quote.recorded", None, None)
        evidence: list[int] = []
        missing: list[dict[str, Any]] = []
        if event is None or event["event_id"] > ctx.anchor.event_id:
            missing.append({"entity_type": "quote", "entity_id": str(row["quote_id"]), "event_type": "quote.recorded"})
        else:
            evidence.append(event["event_id"])
        content = {
            "quote_id": int(row["quote_id"]),
            "price_index": row["price_index"],
            "trade_date": row["trade_date"],
            "close_usd": row["close_usd"],
            "source_revision": row["source_revision"],
            "observed_at": row["observed_at"],
            "supersedes_quote_id": row["supersedes_quote_id"],
            "recorded_by": _actor(ctx.user_roles, row["recorded_by"]),
            "recorded_at": row["recorded_at"],
            "missing_events": missing,
        }
        return content, evidence

    def _content_lot(self, ref: Mapping[str, Any], ctx: _Context) -> tuple[dict[str, Any], list[int]]:
        row = self._require_row(
            ctx.connection.execute("SELECT * FROM inventory_lots WHERE lot_id=?", (ref["lot_id"],)).fetchone(),
            f"库存批次 {ref['lot_id']} 不存在",
        )
        event = ctx.event_for("inventory_lot", row["lot_id"], "inventory.received", None, None)
        evidence: list[int] = []
        missing: list[dict[str, Any]] = []
        if event is None or event["event_id"] > ctx.anchor.event_id:
            missing.append({"entity_type": "inventory_lot", "entity_id": row["lot_id"], "event_type": "inventory.received"})
        else:
            evidence.append(event["event_id"])
        deductions = []
        available = Decimal(row["quantity_barrels"])
        for transfer in ctx.connection.execute(
            "SELECT transfer_id,loaded_barrels,departed_at FROM transfers "
            "WHERE inventory_lot_id=? ORDER BY departed_at,transfer_id",
            (row["lot_id"],),
        ).fetchall():
            if not ctx.visible("transfer", transfer["transfer_id"]):
                continue
            deductions.append({
                "transfer_id": transfer["transfer_id"],
                "loaded_barrels": transfer["loaded_barrels"],
                "departed_at": transfer["departed_at"],
            })
            available -= Decimal(transfer["loaded_barrels"])
            transfer_event = ctx.event_for(
                "transfer", transfer["transfer_id"], "transfer.dispatched", None, None
            )
            if transfer_event is not None:
                evidence.append(transfer_event["event_id"])
        content = {
            "lot_id": row["lot_id"],
            "facility_id": row["facility_id"],
            "product": row["product"],
            "grade": row["grade"],
            "quantity_barrels": row["quantity_barrels"],
            "unit_cost_usd": row["unit_cost_usd"],
            "received_at": row["received_at"],
            "received_by": _actor(ctx.user_roles, row["created_by"]),
            "anchor_available_barrels": format(available, "f"),
            "deductions": deductions,
            "missing_events": missing,
        }
        return content, evidence

    def _nomination_anchor_state(
        self, nomination_id: str, ctx: _Context
    ) -> dict[str, Any]:
        transfers = ctx.connection.execute(
            "SELECT transfer_id FROM transfers WHERE nomination_id=? ORDER BY departed_at DESC,transfer_id",
            (nomination_id,),
        ).fetchall()
        visible_transfer = next(
            (item for item in transfers if ctx.visible("transfer", item["transfer_id"])), None
        )
        if visible_transfer is not None:
            return {"state": "in_transit", "transfer_id": visible_transfer["transfer_id"], "allocation_id": None}
        rows = ctx.connection.execute(
            "SELECT allocation_id,result_json FROM allocation_runs ORDER BY allocation_id DESC"
        ).fetchall()
        for allocation in rows:
            if not ctx.visible("allocation", allocation["allocation_id"]):
                continue
            for entry in _allocation_entries(allocation["result_json"]):
                if entry["nomination_id"] == nomination_id:
                    state = "allocated" if Decimal(entry["allocated_barrels"]) > 0 else "cancelled"
                    return {
                        "state": state,
                        "allocation_id": int(allocation["allocation_id"]),
                        "allocated_barrels": entry["allocated_barrels"],
                    }
        return {"state": "submitted", "allocation_id": None}

    def _content_nomination(self, ref: Mapping[str, Any], ctx: _Context) -> tuple[dict[str, Any], list[int]]:
        row = self._require_row(
            ctx.connection.execute("SELECT * FROM nominations WHERE nomination_id=?", (ref["nomination_id"],)).fetchone(),
            f"提名 {ref['nomination_id']} 不存在",
        )
        event = ctx.event_for("nomination", row["nomination_id"], "nomination.submitted", None, None)
        evidence: list[int] = []
        missing: list[dict[str, Any]] = []
        request_payload = None
        if event is None or event["event_id"] > ctx.anchor.event_id:
            missing.append({"entity_type": "nomination", "entity_id": row["nomination_id"], "event_type": "nomination.submitted"})
        else:
            request_payload = json.loads(event["payload_json"])
            evidence.append(event["event_id"])
        content = {
            "nomination_id": row["nomination_id"],
            "route_id": row["route_id"],
            "shipper_id": row["shipper_id"],
            "service_date": row["service_date"],
            "requested_barrels": row["requested_barrels"],
            "priority": row["priority"],
            "idempotency_key": row["idempotency_key"],
            "submitted_by": _actor(ctx.user_roles, row["submitted_by"]),
            "submitted_at": row["submitted_at"],
            "request_payload": request_payload,
            "anchor_state": self._nomination_anchor_state(row["nomination_id"], ctx),
            "missing_events": missing,
        }
        return content, evidence

    def _content_allocation(self, ref: Mapping[str, Any], ctx: _Context) -> tuple[dict[str, Any], list[int]]:
        row = self._require_row(
            ctx.connection.execute("SELECT * FROM allocation_runs WHERE allocation_id=?", (ref["allocation_id"],)).fetchone(),
            f"分配运行 {ref['allocation_id']} 不存在",
        )
        event = ctx.event_for(
            "route", row["route_id"], "allocation.completed", "allocation_id", int(row["allocation_id"])
        )
        evidence: list[int] = []
        missing: list[dict[str, Any]] = []
        if event is None:
            missing.append({"entity_type": "route", "entity_id": row["route_id"], "event_type": "allocation.completed", "allocation_id": int(row["allocation_id"])})
        else:
            evidence.append(event["event_id"])
        factors = [
            {"outage_id": int(item["outage_id"]), "capacity_percent": item["capacity_percent"]}
            for item in (
                self._outage_anchor_view(outage_id, ctx)
                for outage_id in self._overlapping_outage_ids(row["route_id"], row["service_date"], ctx)
            )
            if item is not None
        ]
        content = {
            "allocation_id": int(row["allocation_id"]),
            "route_id": row["route_id"],
            "service_date": row["service_date"],
            "input_sha256": row["input_sha256"],
            "available_capacity": row["available_capacity"],
            "result": json.loads(row["result_json"]),
            "capacity_factors": factors,
            "created_by": _actor(ctx.user_roles, row["created_by"]),
            "created_at": row["created_at"],
            "missing_events": missing,
        }
        return content, evidence

    def _overlapping_outage_ids(self, route_id: str, service_date: str, ctx: _Context) -> list[int]:
        start = service_date + "T00:00:00Z"
        end = service_date + "T23:59:59Z"
        rows = ctx.connection.execute(
            "SELECT outage_id FROM route_outages "
            "WHERE route_id=? AND state IN ('announced','active') "
            "AND starts_at<=? AND (ends_at IS NULL OR ends_at>=?) ORDER BY outage_id",
            (route_id, end, start),
        ).fetchall()
        return [int(row["outage_id"]) for row in rows if ctx.visible("outage", row["outage_id"])]

    def _outage_anchor_view(self, outage_id: int, ctx: _Context) -> dict[str, Any] | None:
        row = ctx.connection.execute("SELECT * FROM route_outages WHERE outage_id=?", (outage_id,)).fetchone()
        if row is None:
            return None
        return {"outage_id": outage_id, "capacity_percent": row["capacity_percent"]}

    def _content_transfer(self, ref: Mapping[str, Any], ctx: _Context) -> tuple[dict[str, Any], list[int]]:
        row = self._require_row(
            ctx.connection.execute("SELECT * FROM transfers WHERE transfer_id=?", (ref["transfer_id"],)).fetchone(),
            f"转运 {ref['transfer_id']} 不存在",
        )
        event = ctx.event_for("transfer", row["transfer_id"], "transfer.dispatched", None, None)
        evidence: list[int] = []
        missing: list[dict[str, Any]] = []
        if event is None or event["event_id"] > ctx.anchor.event_id:
            missing.append({"entity_type": "transfer", "entity_id": row["transfer_id"], "event_type": "transfer.dispatched"})
        else:
            evidence.append(event["event_id"])
        content = {
            "transfer_id": row["transfer_id"],
            "nomination_id": row["nomination_id"],
            "inventory_lot_id": row["inventory_lot_id"],
            "loaded_barrels": row["loaded_barrels"],
            "expected_delivered_barrels": row["expected_delivered_barrels"],
            "departed_at": row["departed_at"],
            "arrived_at": row["arrived_at"],
            "created_by": _actor(ctx.user_roles, row["created_by"]),
            "missing_events": missing,
        }
        return content, evidence

    def _content_scenario(self, ref: Mapping[str, Any], ctx: _Context) -> tuple[dict[str, Any], list[int]]:
        row = self._require_row(
            ctx.connection.execute("SELECT * FROM supply_scenarios WHERE scenario_id=?", (ref["scenario_id"],)).fetchone(),
            f"情景 {ref['scenario_id']} 不存在",
        )
        evidence: list[int] = []
        missing: list[dict[str, Any]] = []
        created = ctx.event_for("scenario", row["scenario_id"], "scenario.created", None, None)
        approved = ctx.event_for("scenario", row["scenario_id"], "scenario.approved", None, None)
        definition = None
        if created is None or created["event_id"] > ctx.anchor.event_id:
            missing.append({"entity_type": "scenario", "entity_id": row["scenario_id"], "event_type": "scenario.created"})
        else:
            definition = json.loads(created["payload_json"])
            evidence.append(created["event_id"])
        if approved is not None and approved["event_id"] <= ctx.anchor.event_id:
            evidence.append(approved["event_id"])
            anchor_state = "approved"
        elif created is not None and created["event_id"] <= ctx.anchor.event_id:
            anchor_state = "draft"
        else:
            anchor_state = None
        content = {
            "scenario_id": row["scenario_id"],
            "name": row["name"],
            "state_at_anchor": anchor_state,
            "state_recorded": row["state"],
            "revision": row["revision"],
            "content_sha256": row["content_sha256"],
            "definition": definition,
            "created_by": _actor(ctx.user_roles, row["created_by"]),
            "created_at": row["created_at"],
            "missing_events": missing,
        }
        return content, evidence

    def _content_scenario_run(self, ref: Mapping[str, Any], ctx: _Context) -> tuple[dict[str, Any], list[int]]:
        row = self._require_row(
            ctx.connection.execute("SELECT * FROM scenario_runs WHERE run_id=?", (ref["run_id"],)).fetchone(),
            f"情景结果 {ref['run_id']} 不存在",
        )
        event = ctx.event_for("scenario", row["scenario_id"], "scenario.executed", "run_id", int(row["run_id"]))
        evidence: list[int] = []
        missing: list[dict[str, Any]] = []
        if event is None:
            missing.append({"entity_type": "scenario", "entity_id": row["scenario_id"], "event_type": "scenario.executed", "run_id": int(row["run_id"])})
        else:
            evidence.append(event["event_id"])
        content = {
            "run_id": int(row["run_id"]),
            "scenario_id": row["scenario_id"],
            "as_of_date": row["as_of_date"],
            "input_sha256": row["input_sha256"],
            "result": json.loads(row["result_json"]),
            "created_by": _actor(ctx.user_roles, row["created_by"]),
            "created_at": row["created_at"],
            "missing_events": missing,
        }
        return content, evidence

    # ---------------------------------------------------------------- 装包

    def _assemble(
        self,
        job_id: str,
        job: sqlite3.Row,
        ctx: _Context,
        root_ref: Mapping[str, Any],
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        item_rows = ctx.connection.execute(
            "SELECT * FROM evidence_items WHERE job_id=? ORDER BY ordinal", (job_id,)
        ).fetchall()
        items: list[dict[str, Any]] = []
        all_event_ids: set[int] = set()
        for row in item_rows:
            evidence_ids = json.loads(row["evidence_event_ids_json"])
            all_event_ids.update(evidence_ids)
            items.append({
                "item_id": row["item_id"],
                "kind": row["item_kind"],
                "ref": json.loads(row["ref_json"]),
                "status": row["status"],
                "anchor_at": row["anchor_at"],
                "content": None if row["content_json"] is None else json.loads(row["content_json"]),
                "missing_reason": None if row["status"] == "collected" else row["detail_text"],
                "evidence_event_ids": sorted(evidence_ids),
                "sha256": row["item_sha256"],
            })
        items.sort(key=lambda item: item["item_id"])
        all_event_ids.add(ctx.anchor.event_id)
        from_event_id = min(all_event_ids)
        segment_rows = [
            ctx.events[event_id]
            for event_id in range(from_event_id, ctx.anchor.event_id + 1)
            if event_id in ctx.events
        ]
        events = [_event_body(row, ctx.user_roles) for row in segment_rows]
        package = {
            "format": PACKAGE_FORMAT,
            "root": {"kind": job["root_kind"], "ref": root_ref},
            "cutoff": {
                "event_id": ctx.anchor.event_id,
                "event_hash": ctx.anchor.event_hash,
                "at": ctx.anchor.at,
            },
            "items": items,
            "audit_segment": {
                "from_event_id": from_event_id,
                "to_event_id": ctx.anchor.event_id,
                "events": events,
            },
        }
        package_sha = _package_sha256(package)
        manifest = {
            "format": MANIFEST_FORMAT,
            "job_id": job_id,
            "root": package["root"],
            "cutoff": package["cutoff"],
            "items": [
                {
                    "item_id": item["item_id"],
                    "kind": item["kind"],
                    "ref": item["ref"],
                    "status": item["status"],
                    "anchor_at": item["anchor_at"],
                    "sha256": item["sha256"],
                }
                for item in items
            ],
            "audit_segment": {
                "from_event_id": from_event_id,
                "to_event_id": ctx.anchor.event_id,
                "event_count": len(events),
                "head_hash": ctx.anchor.event_hash,
            },
            "item_count": len(items),
            "missing_count": sum(1 for item in items if item["status"] != "collected"),
            "package_sha256": package_sha,
        }
        return package, manifest

    # ---------------------------------------------------------------- 查询

    def get_job(self, job_id: str | None = None, *, root_kind: str | None = None,
                root_ref: Mapping[str, Any] | None = None) -> dict[str, Any]:
        if job_id is None:
            if root_kind is None or root_ref is None:
                raise ValidationFailed("必须提供 job_id 或根对象")
            job_id = f"ev-{root_kind.replace('_', '-')}-{_ref_id(root_kind, root_ref)}"
        row = self._job_row(job_id)
        result = {
            "job_id": row["job_id"],
            "root_kind": row["root_kind"],
            "root_ref": json.loads(row["root_ref"]),
            "state": row["state"],
            "cutoff_event_id": row["cutoff_event_id"],
            "cutoff_head_hash": row["cutoff_head_hash"],
            "cutoff_at": row["cutoff_at"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "error": row["error_text"],
        }
        if row["manifest_json"] is not None:
            result["manifest"] = json.loads(row["manifest_json"])
        if row["package_sha256"] is not None:
            result["package_sha256"] = row["package_sha256"]
        return result

    def get_package(self, job_id: str) -> dict[str, Any]:
        row = self._job_row(job_id)
        if row["package_json"] is None:
            raise InvalidState("证据包尚未生成")
        return json.loads(row["package_json"])

    def export_bundle(self, job_id: str) -> dict[str, Any]:
        job = self._job_row(job_id)
        if job["manifest_json"] is None:
            raise InvalidState("证据包尚未生成")
        return {
            "manifest": json.loads(job["manifest_json"]),
            "package": json.loads(job["package_json"]),
        }


class _MissingReference(Exception):
    pass


# ------------------------------------------------------------------ 离线验证

def verify_bundle(
    bundle_or_package: Mapping[str, Any],
    connection: sqlite3.Connection | None = None,
) -> dict[str, Any]:
    if "package" in bundle_or_package and "manifest" in bundle_or_package:
        manifest = bundle_or_package["manifest"]
        package = bundle_or_package["package"]
    else:
        package = dict(bundle_or_package)
        manifest = None
    findings: list[dict[str, Any]] = []

    findings.extend(_verify_items(package))
    findings.extend(_verify_audit_segment(package))
    package_sha = _package_sha256(package)
    package_sha_matches: bool | None = True
    if manifest is None:
        package_sha_matches = None
    else:
        expected = manifest.get("package_sha256")
        package_sha_matches = expected == package_sha
        if not package_sha_matches:
            findings.append({
                "category": DIGEST_MISMATCH,
                "ref": {"scope": "package"},
                "message": "整包摘要与清单不一致",
                "expected": expected,
                "actual": package_sha,
            })
        findings.extend(_verify_manifest_items(manifest, package))
    if connection is not None:
        findings.extend(_verify_against_database(package, connection))

    categories = [MISSING_REFERENCE, DIGEST_MISMATCH, AUDIT_CHAIN]
    counts = {category: 0 for category in categories}
    for finding in findings:
        counts[finding["category"]] += 1
    findings.sort(key=lambda item: (categories.index(item["category"]), json.dumps(item["ref"], sort_keys=True, ensure_ascii=False), item["message"]))
    return {
        "valid": not findings,
        "package_sha256": package_sha,
        "package_sha256_matches_manifest": package_sha_matches,
        "counts": counts,
        "findings": findings,
    }


def _verify_items(package: Mapping[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for item in package.get("items", []):
        if item.get("status") != "collected":
            findings.append({
                "category": MISSING_REFERENCE,
                "ref": {"item_id": item.get("item_id"), "target": item.get("ref")},
                "message": f"条目 {item.get('item_id')} 的引用缺失：{item.get('missing_reason') or '记录不存在'}",
            })
        content_missing_events = []
        content = item.get("content")
        if isinstance(content, dict):
            content_missing_events = content.get("missing_events") or []
        for missing_event in content_missing_events:
            findings.append({
                "category": MISSING_REFERENCE,
                "ref": {"item_id": item.get("item_id"), "audit_event": missing_event},
                "message": f"条目 {item.get('item_id')} 缺少对应的审计片段",
            })
        actual = _item_sha256(item)
        if actual != item.get("sha256"):
            findings.append({
                "category": DIGEST_MISMATCH,
                "ref": {"item_id": item.get("item_id")},
                "message": "条目摘要不符",
                "expected": item.get("sha256"),
                "actual": actual,
            })
    return findings


def _verify_manifest_items(manifest: Mapping[str, Any], package: Mapping[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    package_items = {item["item_id"]: item for item in package.get("items", [])}
    for listed in manifest.get("items", []):
        item = package_items.get(listed["item_id"])
        if item is None:
            findings.append({
                "category": MISSING_REFERENCE,
                "ref": {"item_id": listed["item_id"]},
                "message": "清单列出的条目不在证据包中",
            })
            continue
        if listed.get("sha256") != item.get("sha256"):
            findings.append({
                "category": DIGEST_MISMATCH,
                "ref": {"item_id": listed["item_id"], "scope": "manifest"},
                "message": "清单中的条目摘要与包内不一致",
                "expected": listed.get("sha256"),
                "actual": item.get("sha256"),
            })
    return findings


def _verify_audit_segment(package: Mapping[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    segment = package.get("audit_segment") or {}
    events = segment.get("events") or []
    cutoff = package.get("cutoff") or {}
    previous_hash = None
    expected_id = segment.get("from_event_id")
    for event in events:
        event_id = event.get("event_id")
        if expected_id is not None and event_id != expected_id:
            findings.append({
                "category": AUDIT_CHAIN,
                "ref": {"event_id": event_id},
                "message": f"审计片段在事件 {expected_id} 处断链（编号不连续）",
            })
        if previous_hash is not None and event.get("previous_hash") != previous_hash:
            findings.append({
                "category": AUDIT_CHAIN,
                "ref": {"event_id": event_id},
                "message": "审计片段 previous_hash 断链",
                "expected": previous_hash,
                "actual": event.get("previous_hash"),
            })
        actual = _recomputed_event_hash(event)
        if actual != event.get("event_hash"):
            findings.append({
                "category": AUDIT_CHAIN,
                "ref": {"event_id": event_id},
                "message": "审计事件摘要不符，内容可能被篡改",
                "expected": event.get("event_hash"),
                "actual": actual,
            })
        previous_hash = event.get("event_hash")
        if expected_id is not None:
            expected_id += 1
    if events:
        last = events[-1]
        if last.get("event_id") != cutoff.get("event_id") or last.get("event_hash") != cutoff.get("event_hash"):
            findings.append({
                "category": AUDIT_CHAIN,
                "ref": {"event_id": cutoff.get("event_id")},
                "message": "审计片段末端与包锚点不一致",
            })
    else:
        findings.append({
            "category": AUDIT_CHAIN,
            "ref": {"scope": "audit_segment"},
            "message": "审计片段为空",
        })
    return findings


def _verify_against_database(package: Mapping[str, Any], connection: sqlite3.Connection) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    cutoff = package.get("cutoff") or {}
    cutoff_id = cutoff.get("event_id")
    row = connection.execute(
        "SELECT * FROM supply_audit_events WHERE event_id=?", (cutoff_id,)
    ).fetchone()
    if row is None:
        findings.append({
            "category": AUDIT_CHAIN,
            "ref": {"event_id": cutoff_id},
            "message": "数据库中找不到包锚点事件",
        })
        return findings
    if row["event_hash"] != cutoff.get("event_hash"):
        findings.append({
            "category": AUDIT_CHAIN,
            "ref": {"event_id": cutoff_id},
            "message": "数据库锚点事件摘要与证据包不一致",
            "expected": cutoff.get("event_hash"),
            "actual": row["event_hash"],
        })
    previous_hash = ZERO_HASH
    for db_event in connection.execute(
        "SELECT * FROM supply_audit_events WHERE event_id<=? ORDER BY event_id", (cutoff_id,)
    ).fetchall():
        if db_event["previous_hash"] != previous_hash:
            findings.append({
                "category": AUDIT_CHAIN,
                "ref": {"event_id": db_event["event_id"]},
                "message": "数据库审计链 previous_hash 断链",
            })
            break
        body = {
            "entity_type": db_event["entity_type"],
            "entity_id": db_event["entity_id"],
            "event_type": db_event["event_type"],
            "actor_id": db_event["actor_id"],
            "payload": json.loads(db_event["payload_json"]),
            "created_at": db_event["created_at"],
            "previous_hash": db_event["previous_hash"],
        }
        actual = hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()
        if actual != db_event["event_hash"]:
            findings.append({
                "category": AUDIT_CHAIN,
                "ref": {"event_id": db_event["event_id"]},
                "message": "数据库审计事件摘要不符",
                "expected": db_event["event_hash"],
                "actual": actual,
            })
            break
        previous_hash = db_event["event_hash"]
    root = package.get("root") or {}
    table, column = ROOT_TABLES.get(root.get("kind"), (None, None))
    if table is not None:
        root_id = (root.get("ref") or {}).get(column)
        exists = connection.execute(
            f"SELECT 1 FROM {table} WHERE {column}=?", (root_id,)
        ).fetchone()
        if exists is None:
            findings.append({
                "category": MISSING_REFERENCE,
                "ref": {"root": root},
                "message": "根对象在数据库中已不存在",
            })
    actor_ids = {event.get("actor", {}).get("user_id") for event in (package.get("audit_segment") or {}).get("events", [])}
    for actor_id in actor_ids:
        if actor_id is None:
            continue
        user = connection.execute("SELECT 1 FROM supply_users WHERE user_id=?", (actor_id,)).fetchone()
        if user is None:
            findings.append({
                "category": MISSING_REFERENCE,
                "ref": {"user_id": actor_id},
                "message": "审计片段中的操作者资料已不存在",
            })
    return findings


# ---------------------------------------------------------------------- CLI

def _parse_root(value: str) -> tuple[str, dict[str, Any]]:
    try:
        root_kind, raw_id = value.split("=", 1)
    except ValueError as exc:
        raise ValidationFailed("根对象格式必须是 allocation=<id>、transfer=<id> 或 scenario_run=<id>") from exc
    if root_kind not in ROOT_KINDS:
        raise ValidationFailed("根对象类型不支持")
    if root_kind == "transfer":
        return root_kind, {"transfer_id": raw_id}
    column = "allocation_id" if root_kind == "allocation" else "run_id"
    try:
        numeric_id = int(raw_id)
    except ValueError as exc:
        raise ValidationFailed("根对象编号必须是整数") from exc
    return root_kind, {column: numeric_id}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="调度决定审计证据包任务")
    database_parent = argparse.ArgumentParser(add_help=False)
    database_parent.add_argument("--database", type=Path, default=Path("oil_supply.sqlite3"))
    verify_parent = argparse.ArgumentParser(add_help=False)
    verify_parent.add_argument("--database", type=Path, default=None)
    subparsers = parser.add_subparsers(dest="command", required=True)

    request_parser = subparsers.add_parser("request", parents=[database_parent], help="创建证据任务")
    request_parser.add_argument("--root", required=True, help="allocation=<id>|transfer=<id>|scenario_run=<id>")
    request_parser.add_argument("--actor", default="audit")

    run_parser = subparsers.add_parser("run", parents=[database_parent], help="续作/完成证据任务")
    run_parser.add_argument("--job", required=True)

    build_parser = subparsers.add_parser("build", parents=[database_parent], help="创建、执行并导出证据包")
    build_parser.add_argument("--root", required=True)
    build_parser.add_argument("--actor", default="audit")
    build_parser.add_argument("--out", type=Path, required=True)

    verify_parser = subparsers.add_parser("verify", parents=[verify_parent], help="离线验证证据包文件")
    verify_parser.add_argument("--file", type=Path, required=True)

    args = parser.parse_args(argv)
    cross_only = args.command == "verify" and args.database is None
    connection = None if cross_only else connect(args.database)
    try:
        service = None if connection is None else EvidenceService(connection)
        if args.command == "request":
            root_kind, ref = _parse_root(args.root)
            print(canonical_json(service.request_package(args.actor, root_kind, ref)))
            return 0
        if args.command == "run":
            print(canonical_json(service.advance_job(args.job)))
            return 0
        if args.command == "build":
            root_kind, ref = _parse_root(args.root)
            job = service.request_package(args.actor, root_kind, ref)
            service.advance_job(job["job_id"])
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(
                canonical_json(service.export_bundle(job["job_id"])), encoding="utf-8"
            )
            print(canonical_json({"job_id": job["job_id"], "path": str(args.out), **service.get_job(job["job_id"])}))
            return 0
        if args.command == "verify":
            bundle = json.loads(args.file.read_text(encoding="utf-8"))
            cross = connect(args.database) if args.database else None
            try:
                report = verify_bundle(bundle, cross)
            finally:
                if cross is not None:
                    cross.close()
            print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
            return 0 if report["valid"] else 2
    except SupplyError as exc:
        print(json.dumps({"error": {"code": exc.code, "message": str(exc)}}, ensure_ascii=False))
        return 1
    finally:
        if connection is not None:
            connection.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
