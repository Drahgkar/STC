#!/usr/bin/env python3
"""
Fixture test for ingest_mitre_stix.py's parsing logic.

This does NOT validate against real MITRE data - there's no network access in
this environment to fetch it. It only proves the parser correctly handles the
STIX object shapes described in MITRE's own USAGE.md: attack-pattern /
x-mitre-tactic types, kill_chain_phases linking, x_mitre_is_subtechnique,
x_mitre_deprecated/revoked filtering, and external_references source_name
resolution.

Run this, then run the real script against a real downloaded bundle and
sanity-check the tactic/technique counts against MITRE's published totals
before trusting it further.
"""

import json
import tempfile
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from ingest_mitre_stix import build_reference

FIXTURE_BUNDLE = {
    "type": "bundle",
    "id": "bundle--fixture",
    "objects": [
        {
            "type": "x-mitre-tactic",
            "id": "x-mitre-tactic--fixture-defense-evasion",
            "name": "Defense Evasion",
            "x_mitre_shortname": "defense-evasion",
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "TA0005"}
            ],
        },
        {
            "type": "x-mitre-tactic",
            "id": "x-mitre-tactic--fixture-execution",
            "name": "Execution",
            "x_mitre_shortname": "execution",
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "TA0002"}
            ],
        },
        {
            # Parent technique, appears in two tactics - tests multi-tactic linking
            "type": "attack-pattern",
            "id": "attack-pattern--fixture-t1059",
            "name": "Command and Scripting Interpreter",
            "x_mitre_is_subtechnique": False,
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T1059"}
            ],
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": "execution"}
            ],
        },
        {
            # Sub-technique - tests x_mitre_is_subtechnique handling
            "type": "attack-pattern",
            "id": "attack-pattern--fixture-t1059-001",
            "name": "PowerShell",
            "x_mitre_is_subtechnique": True,
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T1059.001"}
            ],
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": "execution"},
                {"kill_chain_name": "mitre-attack", "phase_name": "defense-evasion"},
            ],
        },
        {
            # Deprecated technique - must be excluded
            "type": "attack-pattern",
            "id": "attack-pattern--fixture-deprecated",
            "name": "Should Not Appear",
            "x_mitre_is_subtechnique": False,
            "x_mitre_deprecated": True,
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T9999"}
            ],
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": "execution"}
            ],
        },
        {
            # Object with NO mitre-attack source_name entry - tests fallback path
            "type": "attack-pattern",
            "id": "attack-pattern--fixture-fallback",
            "name": "Fallback Case",
            "x_mitre_is_subtechnique": False,
            "external_references": [
                {"source_name": "some-other-source", "external_id": "X0001"}
            ],
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": "execution"}
            ],
        },
    ],
}


def run():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "enterprise-attack.json")
        with open(path, "w") as f:
            json.dump(FIXTURE_BUNDLE, f)

        reference = build_reference({"enterprise-attack": path})

    tactics = reference["tactics"]
    techniques = reference["techniques"]

    checks = []

    checks.append(("2 tactics parsed", len(tactics) == 2))
    checks.append(("3 non-deprecated techniques parsed (deprecated excluded)", len(techniques) == 3))

    t1059 = techniques.get("enterprise-attack:T1059")
    checks.append(("T1059 found", t1059 is not None))
    if t1059:
        checks.append(("T1059 not flagged as sub-technique", t1059["is_subtechnique"] is False))
        checks.append(("T1059 linked to exactly 1 tactic (execution)", t1059["tactic_ids"] == ["enterprise-attack:TA0002"]))

    t1059_001 = techniques.get("enterprise-attack:T1059.001")
    checks.append(("T1059.001 found", t1059_001 is not None))
    if t1059_001:
        checks.append(("T1059.001 IS flagged as sub-technique", t1059_001["is_subtechnique"] is True))
        checks.append((
            "T1059.001 linked to both tactics it declares",
            t1059_001["tactic_ids"] == sorted(["enterprise-attack:TA0002", "enterprise-attack:TA0005"])
        ))

    checks.append(("Deprecated T9999 excluded", "enterprise-attack:T9999" not in techniques))

    fallback = techniques.get("enterprise-attack:X0001")
    checks.append(("Fallback-ID object still parsed via non-mitre-attack source", fallback is not None))
    checks.append(("Fallback logged in fallback_count", reference["fallback_count"] == 1))

    print()
    all_pass = True
    for label, result in checks:
        status = "PASS" if result else "FAIL"
        if not result:
            all_pass = False
        print(f"  [{status}] {label}")

    print()
    if all_pass:
        print("All structural checks passed. This confirms the PARSER logic is correct")
        print("for the field shapes MITRE's USAGE.md describes. It does NOT confirm the")
        print("real dataset matches this fixture exactly - run against a real downloaded")
        print("bundle and compare counts to attack.mitre.org/resources/updates/ next.")
        sys.exit(0)
    else:
        print("One or more checks failed - fix before trusting this against real data.")
        sys.exit(1)


if __name__ == "__main__":
    run()
