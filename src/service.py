from datetime import datetime, timezone
from uuid import uuid4

from .audit import AuditTrail
from .domain import ConflictError, NotFoundError
from .rules import RuleEngine, apply_withdrawal


class DomainService:
    def __init__(self, repository, rules=None):
        self.repository = repository
        self.rules = rules or RuleEngine()
        self.audit = AuditTrail(repository)

    def _lookup(self, kind, field, value):
        return self.repository.find_entities(self.rules.normalize_kind(kind), field, value)

    @staticmethod
    def _enrich(entity):
        if entity["kind"] == "grant":
            data = entity["data"]
            quota = data.get("quota_total") or 0
            used = data.get("used_total") or 0
            data["used_total"] = used
            data["remaining_quota"] = max(quota - used, 0)
        return entity

    def health(self):
        return {"status": "ok" if self.repository.ping() else "error"}

    def create(self, actor, kind, data, idempotency_key=None):
        kind = self.rules.normalize_kind(kind)
        if kind == "withdrawal":
            return self.withdraw(actor, data)
        payload = dict(data or {})
        if idempotency_key:
            existing = self.repository.get_idempotency(actor.user_id, idempotency_key)
            if existing:
                entity = self.repository.get_entity(existing)
                if entity:
                    return entity
        self.rules.validate_create(actor, kind, payload, self._lookup)
        entity_id = str(payload.pop("id", "") or uuid4())
        if self.repository.get_entity(entity_id):
            raise ConflictError("entity already exists: " + entity_id)
        status = self.rules.initial_status(kind)
        entity = self.repository.create_entity(entity_id, kind, status, payload, actor.user_id)
        self.audit.record(entity_id, actor, "create", None, status, {"kind": kind})
        if idempotency_key:
            self.repository.save_idempotency(actor.user_id, idempotency_key, entity_id)
        return entity

    def transition(self, actor, entity_id, action, data=None, expected_version=None):
        entity = self.repository.get_entity(entity_id)
        if not entity:
            raise NotFoundError("entity not found: " + entity_id)
        expected = int(expected_version) if expected_version is not None else entity["version"]
        next_status, patch = self.rules.validate_transition(
            actor, entity, action, dict(data or {}), self._lookup
        )
        merged = dict(entity["data"])
        merged.update(patch)
        updated = self.repository.update_entity(entity_id, expected, next_status, merged)
        self.audit.record(
            entity_id,
            actor,
            action,
            entity["status"],
            updated["status"],
            {"patch": patch},
        )
        return updated

    def withdraw(self, actor, data):
        payload = dict(data or {})
        payload = self.rules.validate_create(actor, "withdrawal", payload, self._lookup)
        withdrawal_id = str(payload.pop("id", "") or uuid4())
        as_of = datetime.now(timezone.utc).date().isoformat()
        entity, _created = self.repository.record_withdrawal(
            withdrawal_id=withdrawal_id,
            grant_id=payload["grant_id"],
            order_no=payload["order_no"],
            data=payload,
            actor=actor,
            apply_fn=lambda grant: apply_withdrawal(grant, payload, as_of),
        )
        return entity

    def get(self, entity_id):
        entity = self.repository.get_entity(entity_id)
        if not entity:
            raise NotFoundError("entity not found: " + entity_id)
        return self._enrich(entity)

    def list(self, kind=None, status=None):
        if kind:
            kind = self.rules.normalize_kind(kind)
        return [self._enrich(entity) for entity in self.repository.list_entities(kind=kind, status=status)]

    def audit_log(self, entity_id=None):
        return self.repository.list_audit(entity_id=entity_id)
