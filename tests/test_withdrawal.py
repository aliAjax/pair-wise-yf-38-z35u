import tempfile
import threading
import unittest
from pathlib import Path

from src.domain import Actor, InvalidTransition, ValidationError
from src.repository import SQLiteRepository
from src.rules import RuleEngine
from src.service import DomainService


class WithdrawalTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = SQLiteRepository(Path(self.tmp.name) / "test.db")
        self.service = DomainService(self.repo, RuleEngine())
        self.admin = Actor("admin", "admin")
        self.applicant = Actor("researcher-1", "applicant")

    def tearDown(self):
        self.tmp.cleanup()

    def _active_grant(self, quota=None, expires="2099-01-01"):
        dataset = self.service.create(
            self.admin, "dataset", {"name": "D", "access_policy": "controlled"}
        )
        data = {
            "application_id": "app-1",
            "dataset_id": dataset["id"],
            "recipient": "researcher-1",
        }
        if quota is not None:
            data["quota_total"] = quota
        grant = self.service.create(self.admin, "grant", data)
        return self.service.transition(
            self.admin,
            grant["id"],
            "activate",
            {"starts_at": "2020-01-01", "expires_at": expires},
        )

    def _withdraw(self, grant_id, order_no, amount, purpose="analysis"):
        return self.service.transition(
            self.applicant,
            grant_id,
            "withdraw",
            {"order_no": order_no, "amount": amount, "purpose": purpose},
        )

    def test_withdraw_updates_balance_and_ledger(self):
        grant = self._active_grant(quota=100)
        updated = self._withdraw(grant["id"], "W-1", 30, "sequencing")
        self.assertEqual(updated["status"], "active")
        self.assertEqual(updated["data"]["used_total"], 30)
        remaining = updated["data"]["quota_total"] - updated["data"]["used_total"]
        self.assertEqual(remaining, 70)
        ledger = updated["data"]["withdrawals"]
        self.assertEqual(len(ledger), 1)
        self.assertEqual(ledger[0]["order_no"], "W-1")
        self.assertEqual(ledger[0]["amount"], 30)
        self.assertEqual(ledger[0]["purpose"], "sequencing")
        self.assertEqual(ledger[0]["recorded_by"], "researcher-1")

    def test_insufficient_balance_not_recorded(self):
        grant = self._active_grant(quota=10)
        with self.assertRaises(ValidationError) as ctx:
            self._withdraw(grant["id"], "W-1", 15)
        message = str(ctx.exception)
        self.assertIn("remaining 10", message)
        self.assertIn("short 5", message)
        current = self.service.get(grant["id"])
        self.assertNotIn("withdrawals", current["data"])
        self.assertNotIn("used_total", current["data"])
        self.assertEqual(current["version"], grant["version"])

    def test_revoked_grant_rejects_withdrawal(self):
        grant = self._active_grant(quota=10)
        self.service.transition(self.admin, grant["id"], "revoke", {"reason": "misuse"})
        with self.assertRaises(InvalidTransition) as ctx:
            self._withdraw(grant["id"], "W-1", 1)
        self.assertIn("revoked", str(ctx.exception))
        self.assertNotIn("withdrawals", self.service.get(grant["id"])["data"])

    def test_expired_status_rejects_withdrawal(self):
        grant = self._active_grant(quota=10)
        self.service.transition(
            self.admin, grant["id"], "expire", {"expired_at": "2026-09-26"}
        )
        with self.assertRaises(InvalidTransition) as ctx:
            self._withdraw(grant["id"], "W-1", 1)
        self.assertIn("expired", str(ctx.exception))

    def test_expired_by_date_rejects_withdrawal(self):
        grant = self._active_grant(quota=10, expires="2020-01-01")
        with self.assertRaises(ValidationError) as ctx:
            self._withdraw(grant["id"], "W-1", 1)
        self.assertIn("expired at 2020-01-01", str(ctx.exception))
        self.assertNotIn("withdrawals", self.service.get(grant["id"])["data"])

    def test_duplicate_order_no_deducts_once(self):
        grant = self._active_grant(quota=100)
        first = self._withdraw(grant["id"], "W-1", 40)
        second = self._withdraw(grant["id"], "W-1", 40)
        self.assertEqual(second["data"]["used_total"], 40)
        self.assertEqual(len(second["data"]["withdrawals"]), 1)
        self.assertEqual(second["version"], first["version"])

    def test_legacy_grant_without_quota_has_zero_balance(self):
        grant = self._active_grant(quota=None)
        with self.assertRaises(ValidationError) as ctx:
            self._withdraw(grant["id"], "W-1", 1)
        self.assertIn("remaining 0", str(ctx.exception))

    def test_invalid_amount_rejected(self):
        grant = self._active_grant(quota=10)
        for bad in (0, -3, "5", True):
            with self.assertRaises(ValidationError):
                self._withdraw(grant["id"], "W-bad", bad)

    def test_negative_quota_rejected_at_create(self):
        with self.assertRaises(ValidationError):
            self.service.create(
                self.admin,
                "grant",
                {
                    "application_id": "app-1",
                    "dataset_id": "ds-1",
                    "recipient": "r",
                    "quota_total": -5,
                },
            )

    def test_concurrent_withdrawals_never_overdraw(self):
        grant = self._active_grant(quota=10)
        results = []

        def worker(i):
            try:
                self._withdraw(grant["id"], "W-%d" % i, 7)
                results.append("ok")
            except Exception as exc:
                results.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        final = self.service.get(grant["id"])
        self.assertEqual(results.count("ok"), 1)
        self.assertIsInstance(
            next(r for r in results if r != "ok"), ValidationError
        )
        self.assertEqual(final["data"]["used_total"], 7)
        self.assertGreaterEqual(
            final["data"]["quota_total"] - final["data"]["used_total"], 0
        )

    def test_concurrent_withdrawals_within_quota_both_recorded(self):
        grant = self._active_grant(quota=10)
        errors = []

        def worker(i, amount):
            try:
                self._withdraw(grant["id"], "W-%d" % i, amount)
            except Exception as exc:
                errors.append(exc)

        threads = [
            threading.Thread(target=worker, args=(i, amount))
            for i, amount in enumerate((4, 5))
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        final = self.service.get(grant["id"])
        self.assertEqual(final["data"]["used_total"], 9)
        self.assertEqual(len(final["data"]["withdrawals"]), 2)


if __name__ == "__main__":
    unittest.main()
