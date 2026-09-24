from __future__ import annotations

import copy
import io
import json
import sqlite3
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timezone
from pathlib import Path

from oil_supply import evidence
from oil_supply.api import JsonApplication
from oil_supply.clock import FrozenClock
from oil_supply.planning import digest
from oil_supply.service import SupplyService
from oil_supply.storage import connect


CLOCK_START = datetime(2026, 9, 24, 8, 0, tzinfo=timezone.utc)


def build_dataset(service: SupplyService) -> None:
    service.create_user("plan", "计划员 彭", "planner")
    service.create_user("dispatch", "调度员 刘", "dispatcher")
    service.create_user("risk", "风控员 汪", "risk")
    service.create_user("audit", "审计员 陈", "auditor")
    service.create_facility("plan", {"facility_id": "field-a", "name": "北部油田", "kind": "storage", "timezone": "Asia/Shanghai", "capacity_barrels": "500000"})
    service.create_facility("plan", {"facility_id": "terminal-b", "name": "沿海终端", "kind": "terminal", "timezone": "Asia/Shanghai", "capacity_barrels": "800000"})
    service.create_route("plan", {"route_id": "pipe-a-b", "origin_id": "field-a", "destination_id": "terminal-b", "product": "crude", "daily_capacity": "100000", "loss_basis_points": 25, "transit_hours": 36})
    service.record_quote("plan", {"price_index": "BRENT", "trade_date": "2026-09-23", "close_usd": "98", "source_revision": "r-23", "observed_at": "2026-09-23T21:00:00Z"})
    service.record_quote("plan", {"price_index": "BRENT", "trade_date": "2026-09-23", "close_usd": "97.8", "source_revision": "r-23b", "observed_at": "2026-09-23T22:00:00Z"})
    service.announce_outage("risk", "pipe-a-b", "2026-09-25T00:00:00Z", "2026-09-25T23:59:59Z", "50", "计划检修")
    service.submit_nomination("dispatch", {"nomination_id": "nom-1", "route_id": "pipe-a-b", "shipper_id": "shipper-1", "service_date": "2026-09-25", "requested_barrels": "40000", "priority": 10, "idempotency_key": "key-1"})
    service.submit_nomination("dispatch", {"nomination_id": "nom-2", "route_id": "pipe-a-b", "shipper_id": "shipper-2", "service_date": "2026-09-25", "requested_barrels": "30000", "priority": 20, "idempotency_key": "key-2"})
    service.allocate("dispatch", "pipe-a-b", "2026-09-25")
    service.add_inventory_lot("dispatch", {"lot_id": "lot-1", "facility_id": "field-a", "product": "crude", "grade": "BRENT", "quantity_barrels": "60000", "unit_cost_usd": "91", "received_at": "2026-09-24T06:00:00Z"})
    service.dispatch_transfer("dispatch", "transfer-1", "nom-1", "lot-1", 2)
    service.create_scenario("plan", {"scenario_id": "restart", "name": "管道恢复", "price_index_drop_percent": "9", "route_capacity_changes": {"pipe-a-b": "20"}, "demand_changes": {"field-a:crude": "-5"}})
    service.approve_scenario("risk", "restart", 1)
    service.run_scenario("plan", "restart", "2026-09-23")


def make_service() -> tuple[sqlite3.Connection, SupplyService]:
    connection = sqlite3.connect(":memory:", isolation_level=None)
    connection.row_factory = sqlite3.Row
    service = SupplyService(connection, FrozenClock(CLOCK_START))
    build_dataset(service)
    return connection, service


def package_keys(package: dict) -> set[str]:
    return {item["key"] for item in package["items"]}


class EvidenceCollectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection, self.service = make_service()

    def tearDown(self) -> None:
        self.connection.close()

    def complete_task(self, root_type: str, root_id: object) -> dict:
        task = self.service.request_evidence_task("audit", root_type, root_id)
        self.service.run_evidence_task("audit", task["task_id"])
        return self.service.evidence_package("audit", task["task_id"])

    def test_allocation_package_collects_references_and_redacts(self) -> None:
        package = self.complete_task("allocation", "1")
        types: dict[str, list[str]] = {}
        for item in package["items"]:
            types.setdefault(item["type"], []).append(item["key"])
        self.assertEqual(
            set(types),
            {"allocation_run", "route", "facility", "outage", "nomination", "audit_event", "user"},
        )
        self.assertEqual(sorted(types["facility"]), ["facility:field-a", "facility:terminal-b"])
        self.assertEqual(types["outage"], ["outage:1"])
        self.assertEqual(sorted(types["nomination"]), ["nomination:nom-1", "nomination:nom-2"])
        # 审计片段只含与线路和提名相关的事件
        audit_events = sorted(
            item["content"]["event_id"] for item in package["items"] if item["type"] == "audit_event"
        )
        self.assertEqual(audit_events, [3, 6, 7, 8, 9])
        # 用户资料按审计权限脱敏
        users = {item["content"]["user_id"]: item["content"] for item in package["items"] if item["type"] == "user"}
        self.assertEqual(set(users), {"plan", "dispatch", "risk"})
        for content in users.values():
            self.assertTrue(content["display_name"].startswith("redacted-"))
            self.assertEqual(content["display_name"], evidence.redacted_display_name(content["user_id"]))
        blob = json.dumps(package, ensure_ascii=False)
        for name in ("计划员 彭", "调度员 刘", "风控员 汪", "审计员 陈"):
            self.assertNotIn(name, blob)
        # 清单稳定排序且逐项摘要一致
        manifest = package["manifest"]
        keys = [entry["key"] for entry in manifest["items"]]
        self.assertEqual(keys, sorted(keys))
        contents = {item["key"]: item["content"] for item in package["items"]}
        for entry in manifest["items"]:
            self.assertEqual(entry["sha256"], digest(contents[entry["key"]]))
        self.assertEqual(package["package_sha256"], digest(manifest))
        self.assertEqual(manifest["audit"]["count"], len(audit_events))
        # 验证通过且三类问题都为空
        report = self.service.verify_evidence_package("audit", package)
        self.assertTrue(report["valid"])
        self.assertEqual(report["missing_references"], [])
        self.assertEqual(report["digest_mismatches"], [])
        self.assertEqual(report["audit_chain_breaks"], [])

    def test_repeated_request_reuses_task_and_same_logical_content(self) -> None:
        first = self.service.request_evidence_task("audit", "allocation", "1")
        second = self.service.request_evidence_task("audit", "allocation", 1)
        self.assertFalse(first["reused"])
        self.assertTrue(second["reused"])
        self.assertEqual(first["task_id"], second["task_id"])
        self.service.run_evidence_task("audit", first["task_id"])
        digest_one = self.service.evidence_task("audit", first["task_id"])["package_sha256"]
        # 相同根版本在另一个相同数据库中得到同一逻辑内容
        other_connection, other_service = make_service()
        try:
            other_task = other_service.request_evidence_task("audit", "allocation", "1")
            other_service.run_evidence_task("audit", other_task["task_id"])
            digest_two = other_service.evidence_task("audit", other_task["task_id"])["package_sha256"]
        finally:
            other_connection.close()
        self.assertEqual(first["task_id"], other_task["task_id"])
        self.assertEqual(digest_one, digest_two)

    def test_snapshot_excludes_writes_after_task_start(self) -> None:
        task = self.service.request_evidence_task("audit", "allocation", "1")
        # 任务启动后的新写入
        self.service.announce_outage("risk", "pipe-a-b", "2026-09-25T00:00:00Z", "2026-09-25T12:00:00Z", "25", "临时降容")
        self.service.submit_nomination("dispatch", {"nomination_id": "nom-3", "route_id": "pipe-a-b", "shipper_id": "shipper-3", "service_date": "2026-09-25", "requested_barrels": "5000", "priority": 30, "idempotency_key": "key-3"})
        self.service.record_quote("plan", {"price_index": "BRENT", "trade_date": "2026-09-24", "close_usd": "97", "source_revision": "r-24", "observed_at": "2026-09-24T21:00:00Z"})
        self.service.run_evidence_task("audit", task["task_id"])
        package = self.service.evidence_package("audit", task["task_id"])
        keys = package_keys(package)
        self.assertIn("outage:1", keys)
        self.assertNotIn("outage:2", keys)
        self.assertNotIn("nomination:nom-3", keys)
        self.assertFalse(any(key.startswith("quote:") for key in keys))
        audit_ids = [item["content"]["event_id"] for item in package["items"] if item["type"] == "audit_event"]
        self.assertEqual(max(audit_ids), 9)
        report = self.service.verify_evidence_package("audit", package)
        self.assertTrue(report["valid"])

    def test_scenario_snapshot_bounds_quote_revisions(self) -> None:
        task = self.service.request_evidence_task("audit", "scenario_run", "1")
        # 任务启动后补录同一交易日的报价修订
        self.service.record_quote("plan", {"price_index": "BRENT", "trade_date": "2026-09-23", "close_usd": "97.5", "source_revision": "r-23c", "observed_at": "2026-09-23T23:00:00Z"})
        self.service.run_evidence_task("audit", task["task_id"])
        package = self.service.evidence_package("audit", task["task_id"])
        quote_keys = sorted(key for key in package_keys(package) if key.startswith("quote:"))
        self.assertEqual(quote_keys, ["quote:1", "quote:2"])

    def test_resume_from_interruption_matches_uninterrupted(self) -> None:
        task = self.service.request_evidence_task("audit", "allocation", "1")
        first = self.service.run_evidence_task("audit", task["task_id"], max_steps=1)
        self.assertEqual(first["state"], "running")
        self.assertEqual(first["cursor"], 1)
        self.assertGreater(first["items"], 0)
        second = self.service.run_evidence_task("audit", task["task_id"], max_steps=2)
        self.assertEqual(second["cursor"], 3)
        final = self.service.run_evidence_task("audit", task["task_id"])
        self.assertEqual(final["state"], "completed")
        self.assertEqual(final["cursor"], final["step_count"])
        other_connection, other_service = make_service()
        try:
            other_task = other_service.request_evidence_task("audit", "allocation", "1")
            other_service.run_evidence_task("audit", other_task["task_id"])
            uninterrupted = other_service.evidence_task("audit", other_task["task_id"])["package_sha256"]
        finally:
            other_connection.close()
        self.assertEqual(final["package_sha256"], uninterrupted)

    def test_failed_task_records_error(self) -> None:
        task = self.service.request_evidence_task("audit", "allocation", "1")
        self.connection.execute("DELETE FROM allocation_runs WHERE allocation_id=1")
        status = self.service.run_evidence_task("audit", task["task_id"])
        self.assertEqual(status["state"], "failed")
        self.assertIn("分配运行不存在", status["error"])

    def test_transfer_package_follows_references(self) -> None:
        package = self.complete_task("transfer", "transfer-1")
        keys = package_keys(package)
        self.assertIn("transfer:transfer-1", keys)
        self.assertIn("nomination:nom-1", keys)
        self.assertIn("allocation_run:1", keys)
        self.assertIn("inventory_lot:lot-1", keys)
        self.assertIn("route:pipe-a-b", keys)
        self.assertIn("outage:1", keys)
        self.assertIn("facility:field-a", keys)
        self.assertIn("facility:terminal-b", keys)
        report = self.service.verify_evidence_package("audit", package)
        self.assertTrue(report["valid"])

    def test_scenario_package_includes_quote_revisions(self) -> None:
        package = self.complete_task("scenario_run", "1")
        keys = package_keys(package)
        self.assertIn("scenario_run:1", keys)
        self.assertIn("scenario:restart", keys)
        self.assertIn("quote:1", keys)
        self.assertIn("quote:2", keys)
        self.assertIn("route:pipe-a-b", keys)
        self.assertIn("inventory_lot:lot-1", keys)
        audit_ids = sorted(
            item["content"]["event_id"] for item in package["items"] if item["type"] == "audit_event"
        )
        self.assertEqual(audit_ids, [12, 13, 14])
        report = self.service.verify_evidence_package("audit", package)
        self.assertTrue(report["valid"])

    def test_unmasked_redaction_keeps_display_names(self) -> None:
        task = evidence.create_task(self.connection, self.service.clock, "audit", "allocation", "1", "unmasked")
        evidence.run_task(self.connection, self.service.clock, task["task_id"])
        package = evidence.export_package(self.connection, task["task_id"])
        users = {item["content"]["user_id"]: item["content"] for item in package["items"] if item["type"] == "user"}
        self.assertEqual(users["plan"]["display_name"], "计划员 彭")
        report = evidence.verify_package(self.connection, package)
        self.assertTrue(report["valid"])


class EvidenceVerificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection, self.service = make_service()
        task = self.service.request_evidence_task("audit", "allocation", "1")
        self.service.run_evidence_task("audit", task["task_id"])
        self.task_id = task["task_id"]
        self.package = self.service.evidence_package("audit", self.task_id)

    def tearDown(self) -> None:
        self.connection.close()

    def verify(self, package: object) -> dict:
        return self.service.verify_evidence_package("audit", package)

    def test_missing_reference_is_reported_separately(self) -> None:
        self.connection.execute("DELETE FROM route_outages WHERE outage_id=1")
        report = self.verify(self.package)
        self.assertFalse(report["valid"])
        self.assertEqual(report["missing_references"], [{"item": "outage:1", "type": "outage", "id": 1}])
        self.assertEqual(report["digest_mismatches"], [])
        self.assertEqual(report["audit_chain_breaks"], [])

    def test_package_tamper_is_digest_mismatch(self) -> None:
        tampered = copy.deepcopy(self.package)
        for item in tampered["items"]:
            if item["key"] == "route:pipe-a-b":
                item["content"]["daily_capacity"] = "1"
        report = self.verify(tampered)
        self.assertFalse(report["valid"])
        self.assertEqual(report["missing_references"], [])
        self.assertEqual(report["audit_chain_breaks"], [])
        mismatched_items = {entry["item"] for entry in report["digest_mismatches"]}
        self.assertIn("route:pipe-a-b", mismatched_items)

    def test_database_tamper_is_digest_mismatch(self) -> None:
        self.connection.execute("UPDATE routes SET daily_capacity='99999' WHERE route_id='pipe-a-b'")
        report = self.verify(self.package)
        self.assertFalse(report["valid"])
        self.assertEqual(report["missing_references"], [])
        self.assertEqual(report["audit_chain_breaks"], [])
        mismatched_items = {entry["item"] for entry in report["digest_mismatches"]}
        self.assertIn("route:pipe-a-b", mismatched_items)

    def test_audit_chain_break_is_reported_separately(self) -> None:
        self.connection.execute("UPDATE supply_audit_events SET payload_json='{}' WHERE event_id=3")
        report = self.verify(self.package)
        self.assertFalse(report["valid"])
        self.assertEqual(report["missing_references"], [])
        self.assertTrue(report["audit_chain_breaks"])
        details = json.dumps(report["audit_chain_breaks"], ensure_ascii=False)
        self.assertIn("数据库审计链断裂", details)

    def test_package_audit_event_tamper_breaks_chain(self) -> None:
        tampered = copy.deepcopy(self.package)
        for item in tampered["items"]:
            if item["type"] == "audit_event" and item["content"]["event_id"] == 3:
                item["content"]["payload"] = {"forged": True}
        report = self.verify(tampered)
        self.assertFalse(report["valid"])
        self.assertTrue(report["digest_mismatches"])
        self.assertTrue(report["audit_chain_breaks"])

    def test_structure_errors_for_malformed_package(self) -> None:
        report = self.verify({"format": "oil-supply-evidence/v1"})
        self.assertFalse(report["valid"])
        self.assertTrue(report["structure_errors"])
        self.assertEqual(report["missing_references"], [])
        self.assertEqual(report["digest_mismatches"], [])
        self.assertEqual(report["audit_chain_breaks"], [])


class EvidenceApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection, self.service = make_service()
        self.app = JsonApplication(self.service)

    def tearDown(self) -> None:
        self.connection.close()

    def post(self, path: str, actor: str, payload: dict) -> tuple[int, dict]:
        response = self.app.handle("POST", path, {"X-Actor-Id": actor}, json.dumps(payload).encode())
        return response.status, response.body

    def get(self, path: str, actor: str) -> tuple[int, dict]:
        response = self.app.handle("GET", path, {"X-Actor-Id": actor})
        return response.status, response.body

    def test_full_flow_over_api(self) -> None:
        status, body = self.post("/evidence/tasks", "audit", {"root_type": "allocation", "root_id": "1"})
        self.assertEqual(status, 201)
        task_id = body["task_id"]
        self.assertEqual(body["state"], "pending")
        status, body = self.post("/evidence/tasks", "audit", {"root_type": "allocation", "root_id": "1"})
        self.assertEqual(status, 200)
        self.assertTrue(body["reused"])
        status, body = self.get(f"/evidence/tasks/{task_id}", "audit")
        self.assertEqual(status, 200)
        self.assertEqual(body["state"], "pending")
        status, body = self.post(f"/evidence/tasks/{task_id}/run", "audit", {})
        self.assertEqual(status, 200)
        self.assertEqual(body["state"], "completed")
        status, package = self.get(f"/evidence/tasks/{task_id}/package", "audit")
        self.assertEqual(status, 200)
        self.assertEqual(package["format"], "oil-supply-evidence/v1")
        status, report = self.post("/evidence/verify", "audit", package)
        self.assertEqual(status, 200)
        self.assertTrue(report["valid"])

    def test_permissions_and_states_over_api(self) -> None:
        status, body = self.post("/evidence/tasks", "plan", {"root_type": "allocation", "root_id": "1"})
        self.assertEqual(status, 403)
        self.assertEqual(body["error"]["code"], "forbidden")
        status, body = self.post("/evidence/tasks", "audit", {"root_type": "allocation", "root_id": "99"})
        self.assertEqual(status, 404)
        status, body = self.post("/evidence/tasks", "audit", {"root_type": "transfer", "root_id": "transfer-1"})
        self.assertEqual(status, 201)
        task_id = body["task_id"]
        status, body = self.get(f"/evidence/tasks/{task_id}/package", "audit")
        self.assertEqual(status, 409)
        self.assertEqual(body["error"]["code"], "invalid_state")
        status, body = self.get(f"/evidence/tasks/{task_id}", "dispatch")
        self.assertEqual(status, 403)


class EvidenceCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workspace = tempfile.TemporaryDirectory()
        self.database = Path(self.workspace.name) / "oil_supply.sqlite3"
        connection = connect(self.database)
        service = SupplyService(connection, FrozenClock(CLOCK_START))
        build_dataset(service)
        connection.close()

    def tearDown(self) -> None:
        self.workspace.cleanup()

    def run_cli(self, *args: str) -> tuple[int, dict]:
        output = io.StringIO()
        with redirect_stdout(output):
            code = evidence.main(["--database", str(self.database), *args])
        return code, json.loads(output.getvalue())

    def test_request_run_export_verify_cycle(self) -> None:
        code, task = self.run_cli("request", "--actor", "audit", "--root-type", "allocation", "--root-id", "1")
        self.assertEqual(code, 0)
        self.assertEqual(task["state"], "pending")
        code, result = self.run_cli("run")
        self.assertEqual(code, 0)
        self.assertEqual(result["tasks"][0]["state"], "completed")
        code, package = self.run_cli("export", "--task", task["task_id"])
        self.assertEqual(code, 0)
        package_file = Path(self.workspace.name) / "package.json"
        package_file.write_text(json.dumps(package, ensure_ascii=False), encoding="utf-8")
        code, report = self.run_cli("verify", "--package", str(package_file))
        self.assertEqual(code, 0)
        self.assertTrue(report["valid"])
        # 篡改数据库审计链后验证失败并指出断链
        connection = connect(self.database)
        connection.execute("UPDATE supply_audit_events SET payload_json='{}' WHERE event_id=1")
        connection.close()
        code, report = self.run_cli("verify", "--package", str(package_file))
        self.assertEqual(code, 1)
        self.assertFalse(report["valid"])
        self.assertTrue(report["audit_chain_breaks"])

    def test_cli_resumes_interrupted_task(self) -> None:
        code, task = self.run_cli("request", "--actor", "audit", "--root-type", "transfer", "--root-id", "transfer-1")
        self.assertEqual(code, 0)
        code, status = self.run_cli("run", "--task", task["task_id"], "--max-steps", "1")
        self.assertEqual(code, 0)
        self.assertEqual(status["state"], "running")
        code, status = self.run_cli("run", "--task", task["task_id"])
        self.assertEqual(code, 0)
        self.assertEqual(status["state"], "completed")
        code, package = self.run_cli("export", "--task", task["task_id"])
        self.assertEqual(code, 0)
        self.assertIn("transfer:transfer-1", package_keys(package))


if __name__ == "__main__":
    unittest.main()
