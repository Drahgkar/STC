#!/usr/bin/env python3
"""
Coverage gap report for STC.

Computes, per domain and per tactic, exactly which MITRE techniques are:
  - COVERED: referenced by at least one source in data_sources.json
  - OUT OF SCOPE: explicitly excluded in out_of_scope_techniques.json, with
    a documented reason
  - GAP: neither of the above - a real, actionable, in-scope technique with
    no source coverage yet

This is meant to replace running an ad-hoc frequency analysis every round -
it gives an exact, current to-do list instead of requiring a fresh manual
query each time.

Sanity checks performed (not just counted, actually flagged as errors):
  - Every out-of-scope ID must exist in the reference (catches typos)
  - No technique should be both covered AND marked out of scope (if a
    source legitimately covers something once marked out of scope, the
    out-of-scope entry is stale and should be removed, not silently ignored)
"""

import json
import argparse
import sys
from collections import defaultdict


def get_covered_techniques(sources_data):
    covered = set()

    def walk(node):
        if "mitre_techniques" in node:
            covered.update(node.get("mitre_techniques", []))
        else:
            for v in node.values():
                walk(v)

    walk(sources_data.get("log_warehouse", {}))
    return covered


def is_out_of_scope(technique_id, out_of_scope_registry):
    """A technique is out of scope if it's explicitly listed, OR if its
    parent technique is listed - a sub-technique inherits its parent's
    scope reasoning by default, since it's a more specific variant of the
    same activity (e.g. T1589.002 Email Addresses is still external OSINT
    just like its parent T1589). Explicit entries always take precedence
    for the technique itself; this only fills in sub-techniques that
    weren't individually listed."""
    if technique_id in out_of_scope_registry:
        return True
    if "." in technique_id.split(":", 1)[1]:
        parent_id = technique_id.rsplit(".", 1)[0]
        return parent_id in out_of_scope_registry
    return False


def get_source_entries(sources_data):
    """Walk log_warehouse and yield (platform, service, source, metadata)
    for every leaf log-source entry, so status reporting can group by
    platform/service without duplicating the tree-walk logic."""
    warehouse = sources_data.get("log_warehouse", {})
    for platform, services in warehouse.items():
        for service, sources in services.items():
            for source, metadata in sources.items():
                if "mitre_techniques" in metadata or "mitre_tactics" in metadata:
                    yield platform, service, source, metadata


def print_status_report(sources_data, detail):
    by_status = defaultdict(list)
    for platform, service, source, metadata in get_source_entries(sources_data):
        status = metadata.get("status", "unknown")
        by_status[status].append(f"{platform}/{service}/{source}")

    total = sum(len(v) for v in by_status.values())
    print("=== Source status breakdown ===")
    for status in ("collected", "planned", "not_collected", "unknown"):
        entries = by_status.get(status, [])
        pct = 100 * len(entries) / total if total else 0
        print(f"  {status:14s} {len(entries):4d}  ({pct:.1f}%)")
        if detail:
            for e in sorted(entries):
                print(f"      {e}")
    unexpected = set(by_status.keys()) - {"collected", "planned", "not_collected", "unknown"}
    if unexpected:
        print(f"  [!] {len(unexpected)} source(s) with an unrecognized status value: {sorted(unexpected)}")
    print(f"  Total sources: {total}")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Report MITRE ATT&CK coverage from data_sources.json, broken down "
                    "by domain and tactic: what's covered, what's explicitly out of "
                    "scope, and what genuine gaps remain.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--sources", default="data_sources.json",
                         help="Path to the source catalog (default: data_sources.json)")
    parser.add_argument("--reference", default="mitre_reference.json",
                         help="Path to the MITRE reference file (default: mitre_reference.json)")
    parser.add_argument("--out-of-scope", default="out_of_scope_techniques.json",
                         help="Path to the out-of-scope registry "
                              "(default: out_of_scope_techniques.json)")
    parser.add_argument("--domain", default="all",
                         choices=["all", "enterprise-attack", "mobile-attack", "ics-attack"],
                         help="Restrict the report to one MITRE ATT&CK domain (default: all)")
    parser.add_argument("--detail", action="store_true", help="List every gap technique, not just counts")
    parser.add_argument("--status", action="store_true",
                         help="Also print a breakdown of sources by their status field "
                              "(collected/planned/not_collected/unknown). Combine with "
                              "--detail to list the actual sources in each status.")
    args = parser.parse_args()

    def load_json_arg(path, label):
        try:
            with open(path, encoding="utf-8") as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"Error: {label} file not found: {path}", file=sys.stderr)
            sys.exit(2)
        except json.JSONDecodeError as e:
            print(f"Error: {path} is not valid JSON: {e}", file=sys.stderr)
            sys.exit(2)

    sources_data = load_json_arg(args.sources, "sources")
    reference_data = load_json_arg(args.reference, "reference")
    out_of_scope_data = load_json_arg(args.out_of_scope, "out-of-scope")

    out_of_scope = out_of_scope_data.get("out_of_scope", {})
    covered = get_covered_techniques(sources_data)

    # Sanity check 1: every out-of-scope ID must actually exist in the reference
    errors = []
    for tid in out_of_scope:
        if tid not in reference_data["techniques"]:
            errors.append(f"out_of_scope_techniques.json references '{tid}' which does not "
                           f"exist in {args.reference} - typo, or reference needs updating")

    # Sanity check 2: nothing should be both covered AND out of scope
    stale_out_of_scope = covered & set(out_of_scope.keys())
    for tid in stale_out_of_scope:
        errors.append(f"'{tid}' is marked out of scope but IS covered by a source - "
                       f"the out-of-scope entry is stale and should be removed")

    if errors:
        print(f"[!] {len(errors)} data integrity issue(s) in the out-of-scope registry:")
        for e in errors:
            print(f"    {e}")
        print()

    domains_to_check = ["enterprise-attack", "mobile-attack", "ics-attack"] if args.domain == "all" else [args.domain]

    grand_total = grand_covered = grand_gap = grand_oos = 0

    for domain in domains_to_check:
        domain_techniques = {k: v for k, v in reference_data["techniques"].items() if k.startswith(domain + ":")}
        domain_tactics = {k: v for k, v in reference_data["tactics"].items() if k.startswith(domain + ":")}

        total = len(domain_techniques)
        domain_covered = covered & set(domain_techniques.keys())
        domain_oos = {t for t in domain_techniques if is_out_of_scope(t, out_of_scope)}
        domain_gap = set(domain_techniques.keys()) - domain_covered - domain_oos

        grand_total += total
        grand_covered += len(domain_covered)
        grand_gap += len(domain_gap)
        grand_oos += len(domain_oos)

        pct_covered = 100 * len(domain_covered) / total if total else 0
        pct_of_in_scope = 100 * len(domain_covered) / (total - len(domain_oos)) if (total - len(domain_oos)) else 0

        print(f"=== {domain} ===")
        print(f"  Total techniques:      {total}")
        print(f"  Covered:               {len(domain_covered)} ({pct_covered:.1f}% of all, "
              f"{pct_of_in_scope:.1f}% of in-scope)")
        print(f"  Out of scope:          {len(domain_oos)}")
        print(f"  GAP (in-scope, uncovered): {len(domain_gap)}")
        print()

        # Per-tactic breakdown within this domain
        gap_by_tactic = defaultdict(list)
        for tid in domain_gap:
            entry = domain_techniques[tid]
            for tac_id in entry.get("tactic_ids", []) or ["(no tactic)"]:
                gap_by_tactic[tac_id].append((tid, entry["name"]))

        if gap_by_tactic:
            print(f"  Gap by tactic:")
            for tac_id in sorted(gap_by_tactic, key=lambda t: -len(gap_by_tactic[t])):
                tac_name = domain_tactics.get(tac_id, {}).get("name", tac_id)
                techs = gap_by_tactic[tac_id]
                print(f"    {len(techs):3d}  {tac_id} - {tac_name}")
                if args.detail:
                    for tid, name in sorted(techs):
                        print(f"           {tid} - {name}")
        print()

    print("=== GRAND TOTAL (all checked domains) ===")
    pct = 100 * grand_covered / grand_total if grand_total else 0
    pct_in_scope = 100 * grand_covered / (grand_total - grand_oos) if (grand_total - grand_oos) else 0
    print(f"  {grand_covered} covered / {grand_total} total techniques ({pct:.1f}% of all, "
          f"{pct_in_scope:.1f}% of in-scope)")
    print(f"  {grand_oos} out of scope, {grand_gap} remaining gap")

    if args.status:
        print()
        print_status_report(sources_data, args.detail)


if __name__ == "__main__":
    main()
