import tempfile
import threading
import unittest
from pathlib import Path

from src.domain import Actor, PermissionDenied, ValidationError
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

    def _active_grant(self, quota=10, starts_at="2000-01-01", expires_at="2099-01-01"):
        dataset = self.service.create(
            self.admin,
            "dataset",
            {"name": "Genome Bank", "access_policy": "controlled"},
        )
        grant_data = {
            "application_id": "app-1",
            "dataset_id": dataset["id"],
            "recipient": "researcher-1",
        }
        if quota is not None:
            grant_data["quota_total"] = quota
            grant = self.service.create(self.admin, "grant", grant_data)
        else:
            # A credential created before the ledger existed has no quota.
            grant = self.repo.create_entity(
                "legacy-grant", "grant", "issued", grant_data, self.admin.user_id
            )
        return self.service.transition(
            self.admin,
            grant["id"],
            "activate",
            {"starts_at": starts_at, "expires_at": expires_at},
        )

    def _withdraw(self, grant_id, quantity, order_no="ORD-1", actor=None, purpose="variant calling"):
        return self.service.create(
            actor or self.applicant,
            "withdrawal",
            {
                "grant_id": grant_id,
                "order_no": order_no,
                "quantity": quantity,
                "purpose": purpose,
            },
        )

    def test_success_updates_balance_and_cumulative_usage(self):
        grant = self._active_grant(quota=10)
        withdrawal = self._withdraw(grant["id"], 4)
        self.assertEqual(withdrawal["status"], "recorded")
        self.assertEqual(withdrawal["data"]["quantity"], 4)
        updated = self.service.get(grant["id"])
        self.assertEqual(updated["data"]["used_total"], 4)
        self.assertEqual(updated["data"]["remaining_quota"], 6)
        self._withdraw(grant["id"], 3, order_no="ORD-2")
        updated = self.service.get(grant["id"])
        self.assertEqual(updated["data"]["used_total"], 7)
        self.assertEqual(updated["data"]["remaining_quota"], 3)

    def test_insufficient_balance_is_rejected_and_not_written(self):
        grant = self._active_grant(quota=10)
        with self.assertRaises(ValidationError) as raised:
            self._withdraw(grant["id"], 11)
        self.assertIn("only 10 remaining", str(raised.exception))
        self.assertEqual(self.service.list("withdrawal"), [])
        self.assertEqual(self.service.get(grant["id"])["data"]["used_total"], 0)

    def test_revoked_grant_is_rejected(self):
        grant = self._active_grant(quota=10)
        self.service.transition(
            self.admin, grant["id"], "revoke", {"reason": "purpose changed"}
        )
        with self.assertRaises(ValidationError) as raised:
            self._withdraw(grant["id"], 1)
        self.assertIn("revoked", str(raised.exception))
        self.assertEqual(self.service.list("withdrawal"), [])

    def test_expired_window_is_rejected(self):
        grant = self._active_grant(
            quota=10, starts_at="2019-01-01", expires_at="2020-01-01"
        )
        with self.assertRaises(ValidationError) as raised:
            self._withdraw(grant["id"], 1)
        self.assertIn("expired at 2020-01-01", str(raised.exception))
        self.assertEqual(self.service.list("withdrawal"), [])

    def test_duplicate_order_no_debits_only_once(self):
        grant = self._active_grant(quota=10)
        first = self._withdraw(grant["id"], 3, order_no="DUP")
        second = self._withdraw(grant["id"], 3, order_no="DUP")
        self.assertEqual(first["id"], second["id"])
        withdrawals = self.service.list("withdrawal")
        self.assertEqual(len(withdrawals), 1)
        updated = self.service.get(grant["id"])
        self.assertEqual(updated["data"]["used_total"], 3)
        self.assertEqual(updated["data"]["remaining_quota"], 7)

    def test_concurrent_submissions_never_overdraw(self):
        grant = self._active_grant(quota=10)
        errors = []

        def take(quantity, order_no):
            try:
                self._withdraw(grant["id"], quantity, order_no=order_no)
            except ValidationError as exc:
                errors.append(str(exc))

        start = threading.Barrier(2)

        def worker(quantity, order_no):
            start.wait()
            take(quantity, order_no)

        threads = [
            threading.Thread(target=worker, args=(6, "C-1")),
            threading.Thread(target=worker, args=(6, "C-2")),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        updated = self.service.get(grant["id"])
        self.assertEqual(len(errors), 1)
        self.assertIn("only 4 remaining", errors[0])
        self.assertEqual(updated["data"]["used_total"], 6)
        self.assertGreaterEqual(updated["data"]["remaining_quota"], 0)

    def test_legacy_grant_without_quota_has_zero_balance(self):
        grant = self._active_grant(quota=None)
        self.assertEqual(self.service.get(grant["id"])["data"]["remaining_quota"], 0)
        with self.assertRaises(ValidationError) as raised:
            self._withdraw(grant["id"], 1)
        self.assertIn("only 0 remaining", str(raised.exception))
        self.assertEqual(self.service.list("withdrawal"), [])

    def test_viewer_cannot_withdraw(self):
        grant = self._active_grant(quota=10)
        with self.assertRaises(PermissionDenied):
            self._withdraw(grant["id"], 1, actor=Actor("viewer-1", "viewer"))

    def test_non_positive_quantity_is_rejected(self):
        grant = self._active_grant(quota=10)
        with self.assertRaises(ValidationError):
            self._withdraw(grant["id"], 0)


if __name__ == "__main__":
    unittest.main()
