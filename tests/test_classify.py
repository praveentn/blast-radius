"""Tests for the bit that has to be right: what counts as irreversible."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from blast_radius.classify import (  # noqa: E402
    EXFILTRATING,
    IRREVERSIBLE,
    MUTATING,
    READONLY,
    SPENDING,
    classify,
)
from blast_radius.scanner import (  # noqa: E402
    capabilities_from_credentials,
    _make_credential,
)


def check(name, expected, description=""):
    got = classify(name, description).tier
    assert got == expected, f"{name!r} -> {got}, expected {expected}"


def test_irreversible_verbs():
    for name in [
        "delete_volume", "volumeDelete", "drop_database", "purge_bucket",
        "terminate_instances", "force_push", "reset_hard", "revoke_key",
        "delete_backup", "wipe_cluster",
    ]:
        check(name, IRREVERSIBLE)


def test_delete_beats_create_when_both_present():
    # "create_or_delete_snapshot" must not land in MUTATING just because
    # "create" appears first in the string.
    check("create_or_delete_snapshot", IRREVERSIBLE)


def test_spending_verbs():
    for name in ["provision_cluster", "scale_service", "run_instances", "transfer_funds"]:
        check(name, SPENDING)


def test_exfiltrating_verbs():
    for name in ["send_slack_message", "email_customer", "upload_export", "get_secret"]:
        check(name, EXFILTRATING)


def test_readonly_verbs():
    for name in ["get_service_status", "list_deployments", "read_logs", "describe_stack"]:
        check(name, READONLY)


def test_unknown_verb_is_not_treated_as_safe():
    # The whole point. An unrecognised tool is assumed to change something.
    check("frobnicate_widget", MUTATING)


def test_gate_detected_and_discounts_weight():
    ungated = classify("delete_volume", "Deletes a volume.")
    gated = classify("delete_volume", "Deletes a volume. Requires explicit human approval.")
    assert ungated.tier == gated.tier == IRREVERSIBLE
    assert gated.gated is True
    assert gated.weight < ungated.weight
    assert gated.nine_second is False
    assert ungated.nine_second is True


def test_recoverable_detected():
    cap = classify("delete_record", "Soft delete, moves to trash with 30 day retention.")
    assert cap.recoverable is True
    assert cap.nine_second is False


def test_authority_gap_on_narrow_sounding_token():
    # The PocketOS shape: named for domains, scoped to the account.
    cred = _make_credential("RAILWAY_DOMAIN_TOKEN", ".env")
    assert cred.provider == "Railway"
    assert cred.authority_gap is True
    assert IRREVERSIBLE in cred.implies


def test_no_gap_flagged_on_honestly_named_token():
    cred = _make_credential("RAILWAY_ACCOUNT_TOKEN", ".env")
    assert cred.provider == "Railway"
    assert cred.authority_gap is False


def test_unknown_credential_is_not_assumed_narrow():
    cred = _make_credential("ACME_WIDGET_API_KEY", ".env")
    assert cred.provider == "unknown"
    assert cred.implies, "an unknown credential must still imply some reach"


def test_ambient_capabilities_are_never_gated():
    creds = [_make_credential("RAILWAY_DOMAIN_TOKEN", ".env")]
    caps = capabilities_from_credentials(creds)
    assert caps, "expected capabilities derived from the credential"
    assert all(not c.gated for c in caps)
    assert any(c.nine_second for c in caps)


if __name__ == "__main__":
    failures = 0
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for test in tests:
        try:
            test()
            print(f"  pass  {test.__name__}")
        except AssertionError as exc:
            failures += 1
            print(f"  FAIL  {test.__name__}: {exc}")
    print(f"\n{len(tests) - failures}/{len(tests)} passed")
    raise SystemExit(1 if failures else 0)
