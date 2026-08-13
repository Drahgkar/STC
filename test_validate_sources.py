#!/usr/bin/env python3
"""
Fixture test for validate_sources.py. Builds a small synthetic reference and
a small synthetic sources file with one of each case the validator claims to
handle, and checks the validator's output matches expectations.

This does not touch a real mitre_reference.json - see the note in
validate_sources.py about running against real output before trusting it in CI.
"""

import sys
import os

sys.path.insert(0, os.path.dirname(__file__))
from validate_sources import validate

FIXTURE_REFERENCE = {
    "tactics": {
        "enterprise-attack:TA0002": {"name": "Execution"},
        "enterprise-attack:TA0005": {"name": "Stealth"},
    },
    "techniques": {
        "enterprise-attack:T1059": {"name": "Command and Scripting Interpreter", "tactic_ids": ["enterprise-attack:TA0002"]},
        "enterprise-attack:T1059.001": {"name": "PowerShell", "tactic_ids": ["enterprise-attack:TA0002"]},
    },
}

FIXTURE_SOURCES = {
    "log_warehouse": {
        "test_platform": {
            "test_service": {
                "valid_entry": {
                    "mitre_tactics": ["enterprise-attack:TA0002"],
                    "mitre_techniques": ["enterprise-attack:T1059"],
                },
                "unnamespaced_entry": {
                    # missing domain prefix - should error
                    "mitre_tactics": ["TA0002"],
                    "mitre_techniques": [],
                },
                "unknown_id_entry": {
                    # well-formed namespace, but ID doesn't exist in reference
                    "mitre_tactics": [],
                    "mitre_techniques": ["enterprise-attack:T9999"],
                },
                "broad_spectrum_entry": {
                    # empty lists, but flagged broad_spectrum - should NOT error or warn
                    "mitre_tactics": [],
                    "mitre_techniques": [],
                    "broad_spectrum": True,
                },
                "empty_unflagged_entry": {
                    # empty lists, NOT flagged broad_spectrum - should warn, not error
                    "mitre_tactics": [],
                    "mitre_techniques": [],
                },
                "wrong_domain_entry": {
                    # well-formed, valid domain keyword, but ID belongs to a domain
                    # not present in the reference at all - should error as not found
                    "mitre_tactics": [],
                    "mitre_techniques": ["mobile-attack:T1456"],
                },
                "extra_nesting_level": {
                    # the real bug this check exists for: an accidental extra level
                    # under the entry means mitre_tactics/mitre_techniques sit one
                    # level deeper than expected. Structured as a NESTED dict here
                    # (not a leaf) so it reaches the depth check rather than the
                    # ID-format check.
                    "unexpected_middle_key": {
                        "mitre_tactics": ["enterprise-attack:TA0002"],
                        "mitre_techniques": ["enterprise-attack:T1059"],
                    }
                },
                "technique_tactic_mismatch_entry": {
                    # the real bug found in the original 80-source catalog: both
                    # IDs are individually valid, but T1059 only belongs to TA0002
                    # per the reference - TA0005 is orphaned here, and (since
                    # nothing else is listed) T1059 has no listed tactic that
                    # actually matches it either. Should produce exactly 2 errors.
                    "mitre_tactics": ["enterprise-attack:TA0005"],
                    "mitre_techniques": ["enterprise-attack:T1059"],
                },
            }
        }
    }
}


def run():
    errors, warnings = validate(FIXTURE_SOURCES, FIXTURE_REFERENCE)

    checks = []

    def has_error_containing(substr):
        return any(substr in e for e in errors)

    def has_warning_containing(substr):
        return any(substr in w for w in warnings)

    checks.append(("valid_entry produces no error", not has_error_containing("valid_entry")))
    checks.append(("unnamespaced_entry flagged as invalid format",
                    has_error_containing("unnamespaced_entry") and has_error_containing("not a valid")))
    checks.append(("unknown_id_entry flagged as not found",
                    has_error_containing("unknown_id_entry") and has_error_containing("not found in mitre_reference.json")))
    checks.append(("broad_spectrum_entry produces no error or warning",
                    not has_error_containing("broad_spectrum_entry") and not has_warning_containing("broad_spectrum_entry")))
    checks.append(("empty_unflagged_entry produces a warning, not an error",
                    has_warning_containing("empty_unflagged_entry") and not has_error_containing("empty_unflagged_entry")))
    checks.append(("wrong_domain_entry (mobile ID, reference has no mobile domain) flagged not found",
                    has_error_containing("wrong_domain_entry") and has_error_containing("not found in mitre_reference.json")))
    checks.append(("extra_nesting_level flagged as wrong depth",
                    has_error_containing("unexpected_middle_key") and has_error_containing("expected exactly 3")))
    checks.append(("technique_tactic_mismatch_entry flagged in both directions",
                    has_error_containing("technique_tactic_mismatch_entry") and
                    sum(1 for e in errors if "technique_tactic_mismatch_entry" in e) == 2))

    print()
    all_pass = True
    for label, result in checks:
        status = "PASS" if result else "FAIL"
        if not result:
            all_pass = False
        print(f"  [{status}] {label}")

    print(f"\n  Total errors: {len(errors)} (expected 6: unnamespaced, unknown_id, wrong_domain, "
          f"extra_nesting_level, technique_tactic_mismatch_entry x2)")
    print(f"  Total warnings: {len(warnings)} (expected 1: empty_unflagged_entry)")
    if len(errors) != 6 or len(warnings) != 1:
        all_pass = False
        print("  [FAIL] error/warning counts don't match expectations")
    else:
        print("  [PASS] error/warning counts match expectations")

    print()
    if all_pass:
        print("All validator checks passed.")
        sys.exit(0)
    else:
        print("One or more checks failed.")
        sys.exit(1)


if __name__ == "__main__":
    run()
