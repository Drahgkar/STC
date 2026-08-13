#!/usr/bin/env python3
"""
Validates data_sources.json against mitre_reference.json.

Enforces the rule this project decided on: every mitre_tactics / mitre_techniques
entry in the source catalog must be an explicitly namespaced ID in the form
"<domain>:<ATT&CK-ID>" (e.g. "enterprise-attack:T1059", "mobile-attack:T1456",
"ics-attack:T0801"), and that ID must actually exist in mitre_reference.json.
A bare "T1059" with no domain prefix is treated as invalid, not defaulted -
that ambiguity is exactly what namespacing was meant to remove.

Exit code 0 = clean, non-zero = at least one problem found. Designed to run
as a CI gate (e.g. a GitLab CI job) so a PR/MR can't merge a source entry
referencing a typo'd or non-existent technique ID.

Checks performed per source entry:
  1. Every string in mitre_tactics / mitre_techniques matches the
     "<domain>:<ID>" pattern.
  2. The domain prefix is one of enterprise-attack / mobile-attack / ics-attack.
  3. The full namespaced ID exists as a key in mitre_reference.json's
     "tactics" or "techniques" dict respectively.
  4. broad_spectrum sources are allowed empty mitre_tactics/mitre_techniques
     lists without triggering an error (that's the documented meaning of the
     flag from Phase 0 - not every EDR alert source maps to a fixed technique
     list).
  5. A source with neither broad_spectrum=true NOR any tactics/techniques
     listed is flagged as a warning (not an error) - it might be intentional,
     might be an incomplete entry, worth a human look either way.
  6. Every source entry (leaf dict containing mitre_tactics/mitre_techniques)
     must sit at EXACTLY depth 3 under log_warehouse - platform/service/category.
     This was added after a real bug: an entry with an accidental extra
     nesting level passed this validator with zero errors under the old
     ID-only checks, but generate_stc_map.py silently dropped it from the
     rendered graph with no warning at all - the leaf's mitre_tactics/
     mitre_techniques data never appeared anywhere. This check exists so that
     class of mistake is caught here, loudly, instead of silently vanishing
     downstream in the generator.
  7. Every listed tactic must be justified by at least one listed technique
     on the same entry (i.e. the tactic appears in that technique's own
     tactic_ids per mitre_reference.json), and conversely every listed
     technique must have at least one of its own tactic_ids present in the
     entry's tactic list. Added after finding 8 real mismatches in the
     original hand-typed catalog - e.g. three entries tagged T1595 (Active
     Scanning) with tactic TA0007 (Discovery), when T1595 actually belongs
     only to TA0043 (Reconnaissance) per MITRE's own data. ID-existence
     checks alone never caught this since both TA0007 and T1595 are
     individually valid IDs - just not valid together. broad_spectrum
     entries are exempt (empty tactics/techniques lists by design).

NOTE: this has been exercised against a hand-built fixture reference file
(see test_validate_sources.py), not against a real mitre_reference.json -
this environment has no network access to generate one. Run it for real
against the mitre_reference.json your fetch_reference.sh / ingest_mitre_stix.py
run already produced before wiring it into CI.
"""

import json
import re
import sys
import argparse

NAMESPACED_ID_RE = re.compile(r"^(enterprise-attack|mobile-attack|ics-attack):(TA?\d{4}(?:\.\d{3})?)$")


EXPECTED_LEAF_DEPTH = 3  # platform / service / category, relative to log_warehouse


def validate(sources_data, reference_data):
    errors = []
    warnings = []

    ref_tactics = set(reference_data.get("tactics", {}).keys())
    ref_techniques = set(reference_data.get("techniques", {}).keys())

    def check_id_list(ids, ref_set, kind, path):
        for entry in ids:
            m = NAMESPACED_ID_RE.match(entry)
            if not m:
                errors.append(f"{'/'.join(path)}: {kind} '{entry}' is not a valid "
                               f"'<domain>:<ID>' namespaced string")
                continue
            if entry not in ref_set:
                errors.append(f"{'/'.join(path)}: {kind} '{entry}' not found in mitre_reference.json "
                               f"(typo, deprecated ID, or reference file needs updating)")

    def walk(node, path, depth):
        if not isinstance(node, dict):
            return
        if "mitre_tactics" in node or "mitre_techniques" in node:
            if depth != EXPECTED_LEAF_DEPTH:
                errors.append(
                    f"{'/'.join(path)}: entry found at depth {depth}, expected exactly "
                    f"{EXPECTED_LEAF_DEPTH} (platform/service/category). This structure "
                    f"will be SILENTLY DROPPED by generate_stc_map.py - its mitre_tactics/"
                    f"mitre_techniques will never appear in the rendered graph."
                )

            tactics = node.get("mitre_tactics", [])
            techniques = node.get("mitre_techniques", [])
            is_broad = node.get("broad_spectrum", False)

            check_id_list(tactics, ref_tactics, "tactic", path)
            check_id_list(techniques, ref_techniques, "technique", path)

            if not is_broad and not tactics and not techniques:
                warnings.append(f"{'/'.join(path)}: no tactics/techniques listed and "
                                 f"not marked broad_spectrum - intentional or incomplete?")

            if not is_broad and tactics and techniques:
                # Only check consistency when every ID is individually valid -
                # an invalid ID already produced its own error above, and
                # cross-checking against a bad ID would just be noise.
                all_tactics_valid = all(NAMESPACED_ID_RE.match(t) and t in ref_tactics for t in tactics)
                all_techniques_valid = all(NAMESPACED_ID_RE.match(t) and t in ref_techniques for t in techniques)
                if all_tactics_valid and all_techniques_valid:
                    technique_tactic_union = set()
                    for tech in techniques:
                        technique_tactic_union.update(reference_data["techniques"][tech]["tactic_ids"])

                    for listed_tactic in tactics:
                        if listed_tactic not in technique_tactic_union:
                            errors.append(
                                f"{'/'.join(path)}: tactic '{listed_tactic}' is listed but no "
                                f"listed technique actually belongs to it (listed techniques "
                                f"{techniques} map to {sorted(technique_tactic_union)})"
                            )

                    for listed_technique in techniques:
                        valid_tactics_for_technique = set(reference_data["techniques"][listed_technique]["tactic_ids"])
                        if not (valid_tactics_for_technique & set(tactics)):
                            errors.append(
                                f"{'/'.join(path)}: technique '{listed_technique}' is listed but none of "
                                f"its actual tactics ({sorted(valid_tactics_for_technique)}) are in the "
                                f"entry's tactic list {tactics}"
                            )
        else:
            for k, v in node.items():
                walk(v, path + [k], depth + 1)

    walk(sources_data.get("log_warehouse", {}), [], 0)
    return errors, warnings


def main():
    parser = argparse.ArgumentParser(
        description="Validate that every MITRE technique/tactic ID referenced in "
                    "data_sources.json is correctly namespaced, actually exists in "
                    "mitre_reference.json, sits at the expected nesting depth, and "
                    "that each listed tactic and technique are mutually consistent. "
                    "See the top of this file for the full reasoning behind each check.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--sources", default="data_sources.json",
                         help="Path to the source catalog to validate (default: data_sources.json)")
    parser.add_argument("--reference", default="mitre_reference.json",
                         help="Path to the MITRE reference file to validate against "
                              "(default: mitre_reference.json)")
    args = parser.parse_args()

    try:
        with open(args.sources, encoding="utf-8") as f:
            sources_data = json.load(f)
    except FileNotFoundError:
        print(f"Error: sources file not found: {args.sources}", file=sys.stderr)
        sys.exit(2)
    except json.JSONDecodeError as e:
        print(f"Error: {args.sources} is not valid JSON: {e}", file=sys.stderr)
        sys.exit(2)

    try:
        with open(args.reference, encoding="utf-8") as f:
            reference_data = json.load(f)
    except FileNotFoundError:
        print(f"Error: reference file not found: {args.reference}", file=sys.stderr)
        print("Run fetch_reference.sh and ingest_mitre_stix.py first.", file=sys.stderr)
        sys.exit(2)
    except json.JSONDecodeError as e:
        print(f"Error: {args.reference} is not valid JSON: {e}", file=sys.stderr)
        sys.exit(2)

    errors, warnings = validate(sources_data, reference_data)

    if warnings:
        print(f"[!] {len(warnings)} warning(s):")
        for w in warnings:
            print(f"    {w}")

    if errors:
        print(f"[x] {len(errors)} error(s):")
        for e in errors:
            print(f"    {e}")
        print()
        print("FAILED")
        sys.exit(1)

    print(f"[+] All MITRE ID references in {args.sources} resolve against {args.reference}")
    print("PASSED")
    sys.exit(0)


if __name__ == "__main__":
    main()
