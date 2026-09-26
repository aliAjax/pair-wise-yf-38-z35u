from datetime import datetime, timedelta

from .domain import (
    ConflictError,
    InvalidTransition,
    PermissionDenied,
    ValidationError,
)


def _validate_dataset(actor, data, lookup):
    if len(data.get("access_policy", "")) < 3:
        raise ValidationError("access_policy is required")


def _validate_application(actor, data, lookup):
    dataset = _find_one(lookup, "dataset", "id", data.get("dataset_id"))
    if not dataset:
        raise ValidationError("dataset does not exist")
    if not data.get("purpose", "").strip():
        raise ValidationError("purpose is required")


def _is_positive_number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and value > 0


def _validate_grant(actor, data, lookup):
    if not _is_positive_number(data.get("quota_total")):
        raise ValidationError("quota_total must be a positive number")


def _validate_withdrawal(actor, data, lookup):
    if not _is_positive_number(data.get("quantity")):
        raise ValidationError("quantity must be a positive number")
    if not str(data.get("purpose", "")).strip():
        raise ValidationError("purpose is required")


def _validate_approve(actor, entity, data, lookup):
    approvals = data.get("approvals") or []
    if len(set(approvals)) < 3:
        raise ValidationError("at least three distinct committee approvals are required")
    if data.get("conflict_of_interest"):
        raise PermissionDenied("conflicted reviewer cannot approve access")


def valid_grant_window(expires_at, as_of):
    return str(expires_at) >= str(as_of)


def _validate_grant_activate(actor, entity, data, lookup):
    if data.get("expires_at") < data.get("starts_at"):
        raise ValidationError("grant expiry must be after start")
    return {"activated_by": actor.user_id}


def apply_withdrawal(grant, payload, as_of):
    """Check a withdrawal against the grant and return the new grant data.

    Raises ValidationError describing the invalid item (revoked/expired
    credential, window not open) or the missing balance.
    """
    if not grant:
        raise ValidationError("grant does not exist")
    if grant["status"] != "active":
        raise ValidationError(
            "grant is %s: withdrawal rejected" % grant["status"]
        )
    data = grant["data"]
    starts_at = data.get("starts_at")
    expires_at = data.get("expires_at")
    if starts_at and str(as_of) < str(starts_at):
        raise ValidationError("grant not yet valid: starts at %s" % starts_at)
    if expires_at and not valid_grant_window(expires_at, as_of):
        raise ValidationError("grant expired at %s" % expires_at)
    # Grants created before the ledger existed have no quota: zero balance.
    quota = data.get("quota_total") or 0
    used = data.get("used_total") or 0
    remaining = quota - used
    quantity = payload["quantity"]
    if quantity > remaining:
        raise ValidationError(
            "insufficient balance: requested %s but only %s remaining"
            % (quantity, remaining)
        )
    updated = dict(data)
    updated["used_total"] = used + quantity
    detail = {
        "grant_id": grant["id"],
        "order_no": payload["order_no"],
        "quantity": quantity,
        "used_total": used + quantity,
        "remaining_quota": remaining - quantity,
    }
    return updated, detail


CUSTOM_CREATE = {'dataset': _validate_dataset, 'application': _validate_application, 'grant': _validate_grant, 'withdrawal': _validate_withdrawal}
CUSTOM_TRANSITIONS = {('application', 'approve'): _validate_approve, ('grant', 'activate'): _validate_grant_activate}


class RuleEngine:
    ALIASES = {'datasets': 'dataset', 'applications': 'application', 'grants': 'grant', 'withdrawals': 'withdrawal'}
    INITIAL_STATUS = {'dataset': 'registered', 'application': 'draft', 'grant': 'issued', 'withdrawal': 'recorded'}
    TRANSITIONS = {'dataset': {'restrict': (('registered',), 'restricted'), 'publish': (('restricted',), 'published')}, 'application': {'submit': (('draft',), 'submitted'), 'review': (('submitted',), 'under_review'), 'approve': (('under_review',), 'approved'), 'reject': (('under_review',), 'rejected'), 'withdraw': (('submitted', 'under_review'), 'withdrawn')}, 'grant': {'activate': (('issued',), 'active'), 'revoke': (('active',), 'revoked'), 'expire': (('active',), 'expired')}}
    CREATE_REQUIRED = {'dataset': ('name', 'access_policy'), 'application': ('dataset_id', 'applicant_id', 'purpose'), 'grant': ('application_id', 'dataset_id', 'recipient', 'quota_total'), 'withdrawal': ('grant_id', 'order_no', 'quantity', 'purpose')}
    ACTION_REQUIRED = {('dataset', 'restrict'): ('reason',), ('application', 'review'): ('committee_id',), ('application', 'approve'): ('approvals', 'terms', 'expires_at'), ('application', 'reject'): ('reason',), ('application', 'withdraw'): ('reason',), ('grant', 'activate'): ('starts_at', 'expires_at'), ('grant', 'revoke'): ('reason',), ('grant', 'expire'): ('expired_at',)}
    CREATE_ROLES = {'dataset': ('admin', 'committee'), 'application': ('admin', 'applicant'), 'grant': ('admin', 'committee'), 'withdrawal': ('admin', 'applicant')}
    ROLE_ACTIONS = {'restrict': ('admin', 'committee'), 'publish': ('admin', 'committee'), 'submit': ('admin', 'applicant'), 'review': ('admin', 'committee'), 'approve': ('admin', 'committee'), 'reject': ('admin', 'committee'), 'withdraw': ('admin', 'applicant'), 'activate': ('admin', 'committee'), 'revoke': ('admin', 'committee'), 'expire': ('admin', 'committee')}

    def normalize_kind(self, kind):
        return self.ALIASES.get(kind, kind)

    def initial_status(self, kind):
        kind = self.normalize_kind(kind)
        if kind not in self.INITIAL_STATUS:
            raise ValidationError("unknown kind: " + str(kind))
        return self.INITIAL_STATUS[kind]

    @staticmethod
    def _ensure_role(actor, allowed):
        if "*" not in allowed and actor.role not in allowed:
            raise PermissionDenied("role %s is not allowed here" % actor.role)

    @staticmethod
    def _require(data, fields):
        for field in fields:
            value = data.get(field)
            if value is None or value == "" or value == [] or value == {}:
                raise ValidationError("missing required field: " + field)

    def validate_create(self, actor, kind, data, lookup=None):
        kind = self.normalize_kind(kind)
        if kind not in self.INITIAL_STATUS:
            raise ValidationError("unknown kind: " + str(kind))
        self._ensure_role(actor, self.CREATE_ROLES.get(kind, ("admin",)))
        self._require(data, self.CREATE_REQUIRED.get(kind, ()))
        custom = CUSTOM_CREATE.get(kind)
        if custom:
            custom(actor, data, lookup)
        return dict(data)

    def validate_transition(self, actor, entity, action, data, lookup=None):
        kind = self.normalize_kind(entity["kind"])
        transition = self.TRANSITIONS.get(kind, {}).get(action)
        if not transition:
            raise InvalidTransition("unknown action %s for %s" % (action, kind))
        allowed_statuses, next_status = transition
        if entity["status"] not in allowed_statuses:
            raise InvalidTransition(
                "cannot %s from status %s" % (action, entity["status"])
            )
        allowed_roles = self.ROLE_ACTIONS.get(
            (kind, action), self.ROLE_ACTIONS.get(action, ("admin",))
        )
        self._ensure_role(actor, allowed_roles)
        self._require(data, self.ACTION_REQUIRED.get((kind, action), ()))
        custom = CUSTOM_TRANSITIONS.get((kind, action))
        extra = custom(actor, entity, data, lookup) if custom else {}
        patch = dict(data)
        if extra:
            patch.update(extra)
        return next_status, patch


def _find_one(lookup, kind, field, value):
    if lookup is None:
        return None
    rows = lookup(kind, field, value) or []
    return rows[0] if rows else None


def _date_ordinal(value):
    return datetime.fromisoformat(str(value)[:10]).date().toordinal()
