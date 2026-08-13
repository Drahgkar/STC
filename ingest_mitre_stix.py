#!/usr/bin/env python3
"""
Phase 1: Build mitre_reference.json from MITRE's authoritative ATT&CK STIX data.

Source: https://github.com/mitre-attack/attack-stix-data (STIX 2.1 JSON)
Domains covered: enterprise-attack, mobile-attack, ics-attack

This replaces hand-typed tactic/technique labels in sources.json with IDs that
can be validated against this file. sources.json should only ever reference
IDs generated here - never free-text technique names typed by a contributor.

STRUCTURAL NOTES (verified against MITRE's own USAGE.md, not assumed):
  - Techniques AND sub-techniques are both STIX type "attack-pattern",
    distinguished by the boolean field x_mitre_is_subtechnique.
  - A technique's ATT&CK ID (e.g. "T1059" or "T1059.001") lives in
    external_references, in the entry whose source_name == "mitre-attack".
    (MITRE's own examples filter on external_id + type=attack-pattern without
    showing the source_name check explicitly - this script filters on
    source_name defensively and falls back to the first external_id present
    if no "mitre-attack" source is found, logging when that fallback fires
    so it's visible rather than silent.)
  - Tactics are STIX type "x-mitre-tactic", with an ATT&CK ID the same way,
    and a short identifier in x_mitre_shortname (e.g. "defense-evasion").
  - A technique is linked to a tactic via kill_chain_phases: phase_name
    matches the tactic's x_mitre_shortname, AND kill_chain_name must match
    the domain ("mitre-attack" for Enterprise, "mitre-mobile-attack" for
    Mobile, "mitre-ics-attack" for ICS) - without that second check a
    phase_name collision across domains could mis-link a technique.
  - Deprecated/revoked objects are marked with x_mitre_deprecated / revoked
    and are excluded here, per MITRE's own recommendation in USAGE.md.

WHAT THIS SCRIPT HAS NOT DONE:
  This has not been run against the live MITRE dataset in this environment -
  the sandbox this was written in has no outbound network access. The parsing
  logic below has only been exercised against a small hand-built STIX-shaped
  fixture (see test_ingest_mitre.py) that matches the field names and
  structure described above. Run this for real, check the printed counts
  against MITRE's published totals (attack.mitre.org/resources/updates/ lists
  the current tactic/technique/sub-technique counts per domain) before trusting
  the output.
"""

import json
import sys
import argparse
from datetime import datetime, timezone

DOMAINS = {
    "enterprise-attack": "mitre-attack",
    "mobile-attack": "mitre-mobile-attack",
    "ics-attack": "mitre-ics-attack",
}

RAW_URL_TEMPLATE = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/{domain}/{domain}.json"


def get_attck_id(stix_obj, fallback_log):
    """Pull the ATT&CK ID (T-number or TA-number) from external_references.
    Prefers the entry with source_name == 'mitre-attack'; falls back to the
    first external_id present and records that fallback so it's auditable."""
    refs = stix_obj.get("external_references", [])
    for ref in refs:
        if ref.get("source_name") == "mitre-attack" and "external_id" in ref:
            return ref["external_id"]
    for ref in refs:
        if "external_id" in ref:
            fallback_log.append(stix_obj.get("id", "<no-id>"))
            return ref["external_id"]
    return None


def parse_domain(stix_bundle, domain_key, kill_chain_name):
    objects = stix_bundle.get("objects", [])
    fallback_log = []

    tactics = {}          # attck_id -> {name, shortname, domain}
    shortname_to_id = {}  # shortname -> attck_id (scoped to this domain)

    for obj in objects:
        if obj.get("type") != "x-mitre-tactic":
            continue
        if obj.get("x_mitre_deprecated") or obj.get("revoked"):
            continue
        attck_id = get_attck_id(obj, fallback_log)
        shortname = obj.get("x_mitre_shortname")
        if not attck_id or not shortname:
            continue
        tactics[attck_id] = {
            "name": obj.get("name"),
            "shortname": shortname,
            "domain": domain_key,
        }
        shortname_to_id[shortname] = attck_id

    techniques = {}  # attck_id -> {name, is_subtechnique, domain, tactic_ids}

    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("x_mitre_deprecated") or obj.get("revoked"):
            continue
        attck_id = get_attck_id(obj, fallback_log)
        if not attck_id:
            continue

        tactic_ids = []
        for phase in obj.get("kill_chain_phases", []):
            if phase.get("kill_chain_name") != kill_chain_name:
                continue
            shortname = phase.get("phase_name")
            if shortname in shortname_to_id:
                tactic_ids.append(f"{domain_key}:{shortname_to_id[shortname]}")

        techniques[attck_id] = {
            "name": obj.get("name"),
            "is_subtechnique": obj.get("x_mitre_is_subtechnique", False),
            "domain": domain_key,
            "tactic_ids": sorted(tactic_ids),
        }

    return tactics, techniques, fallback_log


def build_reference(domain_files):
    """domain_files: dict of domain_key -> path to local STIX JSON already
    downloaded (this script does not fetch over the network itself in this
    environment - see fetch_reference.sh for the download step)."""
    all_tactics = {}
    all_techniques = {}
    total_fallbacks = []

    for domain_key, kill_chain_name in DOMAINS.items():
        path = domain_files.get(domain_key)
        if not path:
            print(f"[!] Skipping {domain_key}: no local file provided", file=sys.stderr)
            continue
        try:
            with open(path, encoding="utf-8") as f:
                bundle = json.load(f)
        except FileNotFoundError:
            print(f"Error: {domain_key} file not found: {path}", file=sys.stderr)
            sys.exit(2)
        except json.JSONDecodeError as e:
            print(f"Error: {path} is not valid JSON: {e}", file=sys.stderr)
            sys.exit(2)

        tactics, techniques, fallback_log = parse_domain(bundle, domain_key, kill_chain_name)
        print(f"[*] {domain_key}: {len(tactics)} tactics, {len(techniques)} techniques/sub-techniques")
        if fallback_log:
            print(f"    [!] {len(fallback_log)} objects used external_id fallback (no 'mitre-attack' source_name found)")

        all_tactics.update({f"{domain_key}:{k}": v for k, v in tactics.items()})
        all_techniques.update({f"{domain_key}:{k}": v for k, v in techniques.items()})
        total_fallbacks.extend(fallback_log)

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": "https://github.com/mitre-attack/attack-stix-data",
        "note": "IDs are namespaced as '<domain>:<ATT&CK-ID>' because the same base ID "
                "does not always mean the same object across Enterprise/Mobile/ICS.",
        "tactics": all_tactics,
        "techniques": all_techniques,
        "fallback_count": len(total_fallbacks),
    }


def main():
    parser = argparse.ArgumentParser(
        description="Build mitre_reference.json from local MITRE ATT&CK STIX bundle files."
    )
    parser.add_argument("--enterprise", help="Path to local enterprise-attack.json")
    parser.add_argument("--mobile", help="Path to local mobile-attack.json")
    parser.add_argument("--ics", help="Path to local ics-attack.json")
    parser.add_argument("-o", "--output", default="mitre_reference.json",
                         help="Path to write the generated reference file to "
                              "(default: mitre_reference.json)")
    args = parser.parse_args()

    domain_files = {}
    if args.enterprise:
        domain_files["enterprise-attack"] = args.enterprise
    if args.mobile:
        domain_files["mobile-attack"] = args.mobile
    if args.ics:
        domain_files["ics-attack"] = args.ics

    if not domain_files:
        print("Error: provide at least one of --enterprise / --mobile / --ics "
              "pointing at a locally downloaded STIX bundle.", file=sys.stderr)
        print(f"Download from, e.g.: {RAW_URL_TEMPLATE.format(domain='enterprise-attack')}", file=sys.stderr)
        sys.exit(1)

    reference = build_reference(domain_files)

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(reference, f, indent=2)
        f.write("\n")

    print(f"[+] Wrote {args.output}")
    if reference["fallback_count"] > 0:
        print(f"[!] {reference['fallback_count']} objects fell back to a non-'mitre-attack' "
              f"external_id source - worth spot-checking those IDs by hand.")


if __name__ == "__main__":
    main()
