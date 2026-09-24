from __future__ import annotations

import io
import json
import sqlite3
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timezone
from pathlib import Path

from oil_supply.api import JsonApplication
from oil_supply.clock import FrozenClock
from oil_supply.evidence import (
    AUDIT_CHAIN,
    DIGEST_MISMATCH,
    MISSING_REFERENCE,
    EvidenceService,
    main as evidence_main,
    verify_bundle,
)
from oil_supply.errors import Forbidden
from oil_supply.service import SupplyService


class EvidenceTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:", isolation_level=None, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self.clock = FrozenClock(datetime(2026, 9, 24, 8, 0, tzinfo=timezone.utc))
        self.service = SupplyService(self.connection, self.clock)
        for user_id, role in (("plan", "planner"), ("dispatch", "dispatcher"), ("risk", "risk"), ("audit", "auditor")):
            self.service.create_user(user_id, "真实姓名-" + user_id, role)
        self.service.create_facility("plan", {"facility_id": "field-a", "name": "北部油田", "kind": "storage", "timezone": "Asia/Shanghai", "capacity_barrels": "500000"})
        self.service.create_facility("plan", {"facility_id": "terminal-b", "name": "沿海终端", "kind": "terminal", "timezone": "Asia/Shanghai", "capacity_barrels": "800000"})
        self.service.create_route("plan", {"route_id": "pipe-a-b", "origin_id": "field-a", "destination_id": "terminal-b", "product": "crude", "daily_capacity": "100000", "loss_basis_points": 25, "transit_hours": 36})
        self.evidence = EvidenceService(self.connection, self.clock)

    def tearDown(self) -> None:
        self.connection.close()

    def quote(self, day: int, close: str, revision: str | None = None) -> None:
        self.service.record_quote("plan", {"price_index": "BRENT", "trade_date": f"2026-09-{day}", "close_usd": close, "source_revision": revision or f"r-{day}", "observed_at": f"2026-09-{day}T21:00:00Z"})

    def build_transfer(self) -> tuple[int, str]:
        self.service.announce_outage("risk", "pipe-a-b", "2026-09-25T00:00:00Z", "2026-09-25T23:59:59Z", "50", "检修")
        self.service.submit_nomination("dispatch", {"nomination_id": "nom-1", "route_id": "pipe-a-b", "shipper_id": "shipper-1", "service_date": "2026-09-25", "requested_barrels": "40000", "priority": 10, "idempotency_key": "key-1"})
        self.service.submit_nomination("dispatch", {"nomination_id": "nom-2", "route_id": "pipe-a-b", "shipper_id": "shipper-2", "service_date": "2026-09-25", "requested_barrels": "30000", "priority": 20, "idempotency_key": "key-2"})
        allocation = self.service.allocate("dispatch", "pipe-a-b", "2026-09-25")
        self.service.add_inventory_lot("dispatch", {"lot_id": "lot-1", "facility_id": "field-a", "product": "crude", "grade": "BRENT", "quantity_barrels": "60000", "unit_cost_usd": "91", "received_at": "2026-09-24T06:00:00Z"})
        transfer = self.service.dispatch_transfer("dispatch", "transfer-1", "nom-1", "lot-1", 2)
        return allocation["allocation_id"], transfer["transfer_id"]

    def build_package(self, root_kind: str, ref: dict) -> dict:
        job = self.evidence.request_package("audit", root_kind, ref)
        self.assertFalse(job["reused"])
        completed = self.evidence.advance_job(job["job_id"])
        self.assertEqual(completed["state"], "ready")
        return self.evidence.export_bundle(job["job_id"])


class AllocationEvidenceTests(EvidenceTestBase):
    def test_package_collects_reference_closure_and_verifies(self) -> None:
        allocation_id, _ = self.build_transfer()
        bundle = self.build_package("allocation", {"allocation_id": allocation_id})
        package, manifest = bundle["package"], bundle["manifest"]
        kinds = {item["kind"] for item in package["items"]}
        self.assertIn("allocation", kinds)
        self.assertIn("route", kinds)
        self.assertIn("facility", kinds)
        self.assertIn("outage", kinds)
        self.assertIn("nomination", kinds)
        item_ids = {item["item_id"] for item in package["items"]}
        self.assertIn("outage:1", item_ids)
        self.assertIn("nomination:nom-2", item_ids)
        report = verify_bundle(bundle, self.connection)
        self.assertTrue(report["valid"], report["findings"])
        self.assertEqual(manifest["package_sha256"], report["package_sha256"])
        self.assertEqual(manifest["missing_count"], 0)
        self.assertNotIn("真实姓名", json.dumps(package, ensure_ascii=False))

    def test_cutoff_is_root_anchor_and_later_writes_never_mix_in(self) -> None:
        allocation_id, transfer_id = self.build_transfer()
        bundle = self.build_package("allocation", {"allocation_id": allocation_id})
        chain_head = self.connection.execute("SELECT max(event_id) m FROM supply_audit_events").fetchone()["m"]
        self.assertEqual(bundle["package"]["cutoff"]["event_id"], self._event_id("allocation.completed"))
        self.assertLess(bundle["package"]["cutoff"]["event_id"], chain_head)
        first_sha = bundle["manifest"]["package_sha256"]
        # 任务之后的新写入：新停运、新提名、新转运都不得进入。
        self.clock.advance(hours=2)
        self.service.announce_outage("risk", "pipe-a-b", "2026-09-26T00:00:00Z", "2026-09-26T23:59:59Z", "0", "突发停输")
        again = self.evidence.request_package("audit", "allocation", {"allocation_id": allocation_id})
        self.assertTrue(again["reused"])
        self.evidence.advance_job(again["job_id"])
        second_bundle = self.evidence.export_bundle(again["job_id"])
        self.assertEqual(second_bundle["manifest"]["package_sha256"], first_sha)

    def _event_id(self, event_type: str) -> int:
        return self.connection.execute(
            "SELECT event_id FROM supply_audit_events WHERE event_type=? ORDER BY event_id", (event_type,)
        ).fetchone()["event_id"]

    def test_repeated_request_has_identical_logical_content(self) -> None:
        allocation_id, _ = self.build_transfer()
        first = self.build_package("allocation", {"allocation_id": allocation_id})
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "second.sqlite3"
            connection = sqlite3.connect(db_path, isolation_level=None)
            connection.row_factory = sqlite3.Row
            service = SupplyService(connection, self.clock)
            for user_id, role in (("plan", "planner"), ("dispatch", "dispatcher"), ("risk", "risk"), ("audit", "auditor")):
                service.create_user(user_id, user_id, role)
            service.create_facility("plan", {"facility_id": "field-a", "name": "北部油田", "kind": "storage", "timezone": "Asia/Shanghai", "capacity_barrels": "500000"})
            service.create_facility("plan", {"facility_id": "terminal-b", "name": "沿海终端", "kind": "terminal", "timezone": "Asia/Shanghai", "capacity_barrels": "800000"})
            service.create_route("plan", {"route_id": "pipe-a-b", "origin_id": "field-a", "destination_id": "terminal-b", "product": "crude", "daily_capacity": "100000", "loss_basis_points": 25, "transit_hours": 36})
            service.announce_outage("risk", "pipe-a-b", "2026-09-25T00:00:00Z", "2026-09-25T23:59:59Z", "50", "检修")
            service.submit_nomination("dispatch", {"nomination_id": "nom-1", "route_id": "pipe-a-b", "shipper_id": "shipper-1", "service_date": "2026-09-25", "requested_barrels": "40000", "priority": 10, "idempotency_key": "key-1"})
            service.submit_nomination("dispatch", {"nomination_id": "nom-2", "route_id": "pipe-a-b", "shipper_id": "shipper-2", "service_date": "2026-09-25", "requested_barrels": "30000", "priority": 20, "idempotency_key": "key-2"})
            allocation = service.allocate("dispatch", "pipe-a-b", "2026-09-25")
            other_evidence = EvidenceService(connection, self.clock)
            job = other_evidence.request_package("audit", "allocation", {"allocation_id": allocation["allocation_id"]})
            other_evidence.advance_job(job["job_id"])
            second = other_evidence.export_bundle(job["job_id"])
            connection.close()
        self.assertEqual(second["manifest"]["package_sha256"], first["manifest"]["package_sha256"])

    def test_only_auditor_may_request(self) -> None:
        allocation_id, _ = self.build_transfer()
        with self.assertRaises(Forbidden):
            self.evidence.request_package("dispatch", "allocation", {"allocation_id": allocation_id})


class TransferEvidenceTests(EvidenceTestBase):
    def test_transfer_package_reconstructs_lot_version(self) -> None:
        _, transfer_id = self.build_transfer()
        bundle = self.build_package("transfer", {"transfer_id": transfer_id})
        package = bundle["package"]
        lots = [item for item in package["items"] if item["kind"] == "lot"]
        self.assertEqual(len(lots), 1)
        lot = lots[0]["content"]
        self.assertEqual(lot["anchor_available_barrels"], "20000.000")
        self.assertEqual(lot["deductions"][0]["transfer_id"], "transfer-1")
        allocations = [item for item in package["items"] if item["kind"] == "allocation"]
        self.assertEqual(len(allocations), 1)
        report = verify_bundle(bundle, self.connection)
        self.assertTrue(report["valid"], report["findings"])
        self.assertEqual(package["cutoff"]["event_id"], self._event_id("transfer.dispatched"))

    def _event_id(self, event_type: str) -> int:
        return self.connection.execute(
            "SELECT event_id FROM supply_audit_events WHERE event_type=? ORDER BY event_id", (event_type,)
        ).fetchone()["event_id"]


class ScenarioEvidenceTests(EvidenceTestBase):
    def test_scenario_package_includes_quote_revision_chain(self) -> None:
        self.quote(23, "98")
        self.quote(23, "97.8", "r-23-corrected")
        self.service.add_inventory_lot("dispatch", {"lot_id": "lot-1", "facility_id": "field-a", "product": "crude", "grade": "BRENT", "quantity_barrels": "60000", "unit_cost_usd": "91", "received_at": "2026-09-24T06:00:00Z"})
        self.service.create_scenario("plan", {"scenario_id": "restart", "name": "管道恢复", "price_index_drop_percent": "9", "route_capacity_changes": {"pipe-a-b": "20"}, "demand_changes": {"field-a:crude": "-5"}})
        self.service.approve_scenario("risk", "restart", 1)
        run = self.service.run_scenario("plan", "restart", "2026-09-23")
        bundle = self.build_package("scenario_run", {"run_id": run["run_id"]})
        quotes = sorted(
            (item["content"] for item in bundle["package"]["items"] if item["kind"] == "quote"),
            key=lambda content: content["quote_id"],
        )
        self.assertEqual(len(quotes), 2)
        self.assertEqual(quotes[1]["supersedes_quote_id"], quotes[0]["quote_id"])
        scenarios = [item for item in bundle["package"]["items"] if item["kind"] == "scenario"]
        self.assertEqual(scenarios[0]["content"]["state_at_anchor"], "approved")
        report = verify_bundle(bundle, self.connection)
        self.assertTrue(report["valid"], report["findings"])


class ResumeTests(EvidenceTestBase):
    def test_interrupted_job_resumes_from_sqlite(self) -> None:
        allocation_id, _ = self.build_transfer()
        job = self.evidence.request_package("audit", "allocation", {"allocation_id": allocation_id})
        original = self.evidence._build_content
        calls = {"count": 0}

        def flaky(kind, ref, ctx):
            calls["count"] += 1
            if calls["count"] == 2:
                raise RuntimeError("模拟任务中断")
            return original(kind, ref, ctx)

        self.evidence._build_content = flaky  # type: ignore[method-assign]
        with self.assertRaises(RuntimeError):
            self.evidence.advance_job(job["job_id"])
        state = self.connection.execute("SELECT state FROM evidence_jobs").fetchone()["state"]
        self.assertEqual(state, "failed")
        partial = self.connection.execute(
            "SELECT count(*) c FROM evidence_items WHERE status='collected'"
        ).fetchone()["c"]
        self.assertGreaterEqual(partial, 1)
        self.evidence._build_content = original  # type: ignore[method-assign]
        completed = self.evidence.advance_job(job["job_id"])
        self.assertEqual(completed["state"], "ready")
        bundle = self.evidence.export_bundle(job["job_id"])
        self.assertTrue(verify_bundle(bundle, self.connection)["valid"])


class VerificationTests(EvidenceTestBase):
    def test_tampered_item_digest_is_flagged(self) -> None:
        allocation_id, _ = self.build_transfer()
        bundle = self.build_package("allocation", {"allocation_id": allocation_id})
        route = next(item for item in bundle["package"]["items"] if item["kind"] == "route")
        route["content"]["daily_capacity"] = "999999"
        report = verify_bundle(bundle)
        self.assertFalse(report["valid"])
        self.assertGreaterEqual(report["counts"][DIGEST_MISMATCH], 1)
        self.assertEqual(report["counts"][MISSING_REFERENCE], 0)
        self.assertEqual(report["counts"][AUDIT_CHAIN], 0)

    def test_broken_audit_chain_is_flagged_separately(self) -> None:
        allocation_id, _ = self.build_transfer()
        bundle = self.build_package("allocation", {"allocation_id": allocation_id})
        event = bundle["package"]["audit_segment"]["events"][0]
        event["payload"]["tampered"] = True
        report = verify_bundle(bundle)
        chain_findings = [f for f in report["findings"] if f["category"] == AUDIT_CHAIN]
        self.assertTrue(chain_findings)
        self.assertTrue(any("摘要" in f["message"] for f in chain_findings))
        # 审计事件不在条目层，条目摘要不受影响；只有整包摘要必然改变。
        item_digest = [
            f for f in report["findings"]
            if f["category"] == DIGEST_MISMATCH and f["ref"].get("scope") != "package"
        ]
        self.assertEqual(item_digest, [])
        self.assertEqual(report["counts"][MISSING_REFERENCE], 0)

    def test_missing_reference_is_flagged(self) -> None:
        allocation_id, _ = self.build_transfer()
        job = self.evidence.request_package("audit", "allocation", {"allocation_id": allocation_id})
        self.connection.execute("DELETE FROM nominations WHERE nomination_id='nom-2'")
        self.evidence.advance_job(job["job_id"])
        bundle = self.evidence.export_bundle(job["job_id"])
        report = verify_bundle(bundle)
        self.assertFalse(report["valid"])
        self.assertGreaterEqual(report["counts"][MISSING_REFERENCE], 1)
        self.assertEqual(report["counts"][DIGEST_MISMATCH], 0)
        missing = [f for f in report["findings"] if f["category"] == MISSING_REFERENCE]
        self.assertTrue(any("nom-2" in json.dumps(f["ref"], ensure_ascii=False) for f in missing))

    def test_package_digest_mismatch_with_manifest(self) -> None:
        allocation_id, _ = self.build_transfer()
        bundle = self.build_package("allocation", {"allocation_id": allocation_id})
        bundle["manifest"]["package_sha256"] = "0" * 64
        report = verify_bundle(bundle)
        self.assertFalse(report["package_sha256_matches_manifest"])
        self.assertGreaterEqual(report["counts"][DIGEST_MISMATCH], 1)


class ApiEvidenceTests(EvidenceTestBase):
    def test_api_background_job_and_verify(self) -> None:
        allocation_id, _ = self.build_transfer()
        app = JsonApplication(self.service, self.evidence)
        response = app.handle(
            "POST", "/evidence/packages", {"X-Actor-Id": "audit"},
            json.dumps({"root_kind": "allocation", "allocation_id": allocation_id}).encode(),
        )
        self.assertEqual(response.status, 202)
        job_id = response.body["job_id"]
        for _ in range(100):
            status = app.handle("GET", f"/evidence/jobs/{job_id}", {"X-Actor-Id": "audit"})
            if status.body["state"] == "ready":
                break
            import time

            time.sleep(0.01)
        self.assertEqual(status.body["state"], "ready")
        bundle_response = app.handle("GET", f"/evidence/jobs/{job_id}/package", {"X-Actor-Id": "audit"})
        self.assertEqual(bundle_response.status, 200)
        verify = app.handle(
            "POST", "/evidence/verify", {"X-Actor-Id": "audit"},
            json.dumps({"bundle": bundle_response.body}).encode(),
        )
        self.assertEqual(verify.status, 200)
        self.assertTrue(verify.body["valid"], verify.body["findings"])
        forbidden = app.handle(
            "POST", "/evidence/packages", {"X-Actor-Id": "plan"},
            json.dumps({"root_kind": "allocation", "allocation_id": allocation_id}).encode(),
        )
        self.assertEqual(forbidden.status, 403)


class CliEvidenceTests(EvidenceTestBase):
    def test_build_and_verify_cli(self) -> None:
        allocation_id, _ = self.build_transfer()
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            db_path = tmp_path / "supply.sqlite3"
            backup = sqlite3.connect(db_path)
            self.connection.backup(backup)
            backup.close()
            out_path = tmp_path / "bundle.json"
            output = io.StringIO()
            with redirect_stdout(output):
                code = evidence_main([
                    "build", "--database", str(db_path),
                    "--root", f"allocation={allocation_id}", "--out", str(out_path),
                ])
            self.assertEqual(code, 0)
            self.assertTrue(out_path.exists())
            result = io.StringIO()
            with redirect_stdout(result):
                code = evidence_main(["verify", "--file", str(out_path), "--database", str(db_path)])
            self.assertEqual(code, 0)
            report = json.loads(result.getvalue())
            self.assertTrue(report["valid"])


if __name__ == "__main__":
    unittest.main()
