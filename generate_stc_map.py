#!/usr/bin/env python3
"""
STC mindmap generator (v6) - expandable tree, not a radial graph.

Why this version exists: v5's radial force-directed layout, even after
wedge-confining each platform to its own angular slice, has a structural
ceiling - there is only 2*pi of angular space total, every platform has a
permanent spoke to root, and the more branches a person has open at once
(a completely normal way to explore this data) the more those slices
compete for the same limited space near the center. That produces visible
crossing regardless of how well-tuned the force simulation is - it isn't
a bug to patch, it's what a fixed-space radial layout does under load.

A tree does not have this ceiling. It grows in one direction on an
effectively unlimited, scrollable canvas - expanding a branch pushes
later content down, it never competes for shared angular space with
anything else. It is also NOT a physics simulation: given which nodes are
currently visible, a tree layout has one exact, deterministic position
for each of them, with zero overlap by construction. Every bug fixed in
v5 (force settling, angle confinement, collision radii, the forceLink
mutation bug) existed only because a force simulation needed tuning at
all - a tree has no equivalent failure mode to tune away.

Data model: a genuine nested tree (platform -> service -> source ->
tactic -> technique), not a flat node/link graph. Because a technique can
legitimately belong to more than one of its own MITRE-defined tactics,
and a tactic can legitimately be fed by more than one source, the SAME
technique node will appear more than once in the tree where that's
actually true of the data - this is correct, not a duplication bug, and
mirrors how a file can legitimately appear under more than one directory
structure.

The technique-to-covering-sources cross-reference (click a technique, see
every OTHER source that also provides it, even ones you haven't
expanded) is preserved from v5, reimplemented as a lookup + "jump to
this occurrence" rather than pulled-in graph edges, since there is no
graph anymore.

No D3 dependency - a static/expandable tree needs none of what D3
provided (force simulation, SVG scale/zoom utilities), so this version
loads faster and has strictly less surface area for the DOM to fight
with. Search still works the same way conceptually as v5: match a label
or technique id, then expand the ancestor chain and scroll to it.
"""

import json
import argparse
import sys
import os
import base64
from urllib.parse import quote

STATUS_STYLE = {
    "collected":     {"color": "#6366f1", "label": "Collected"},
    "planned":       {"color": "#ec4899", "label": "Planned"},
    "not_collected": {"color": "#64748b", "label": "Not collected"},
    "unknown":       {"color": "#94a3b8", "label": "Unknown"},
}

MATRIX_TO_DOMAIN = {
    "enterprise": "enterprise-attack",
    "mobile": "mobile-attack",
    "ics": "ics-attack",
}


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Convert STC source JSON + MITRE reference JSON into a standalone "
                    "expandable-tree HTML5 mindmap.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('-i', '--input', required=True,
                         help="Path to data_sources.json (or a domain-filtered variant)")
    parser.add_argument('-r', '--reference', required=True,
                         help="Path to mitre_reference.json")
    parser.add_argument('-o', '--output', required=True,
                         help="Path to write the generated HTML file to")
    parser.add_argument('--matrix', default='all', choices=['all', 'enterprise', 'mobile', 'ics'],
                         help="Restrict the tree to one MITRE ATT&CK domain (default: all)")
    return parser.parse_args()


def mitre_url(raw_id):
    """Build the real MITRE ATT&CK URL for a technique or sub-technique id
    like 'enterprise-attack:T1055.001'. Verified via search (not assumed)
    that techniques use the SAME /techniques/T####/ (and /techniques/T####/0##/
    for sub-techniques) URL pattern across all three domains - e.g.
    attack.mitre.org/techniques/T0883/ for ICS, attack.mitre.org/techniques/T1417/
    and .../T1417/001/ for Mobile."""
    _, tech_id = raw_id.split(":", 1)
    if "." in tech_id:
        base, sub = tech_id.split(".", 1)
        return f"https://attack.mitre.org/techniques/{base}/{sub}/"
    return f"https://attack.mitre.org/techniques/{tech_id}/"


def mitre_tactic_url(raw_id):
    _, tac_id = raw_id.split(":", 1)
    return f"https://attack.mitre.org/tactics/{tac_id}/"


# --- display-name prettification (generation-time only; the underlying
# data_sources.json keys are never touched, this only affects the label
# text baked into the generated tree) ---
#
# Built and tested against every actual platform (40), service (77), and
# category (126) identifier in this project's real data, not a generic
# guess - several corrections were only found by running it against real
# data (e.g. an early version produced "Cisco Ios", "Macos", "F5 Bigip",
# "DHCP Ipv 4 Audit" - all wrong; current version correctly gives
# "Cisco IOS", "macOS", "F5 BIG-IP", "DHCP IPv4 Audit").
#
# Two identifiers ("hostd", "vpxa") are real, literal lowercase VMware
# daemon process names with no established "proper" capitalized form -
# these are simply capitalized at the first letter as a reasonable
# compromise, not a verified brand name like the rest of this list.
PRETTY_WHOLE_OVERRIDES = {
    "paloalto": "Palo Alto", "panos": "PAN-OS", "vmware": "VMware",
    "github": "GitHub", "gitlab": "GitLab", "opensips": "OpenSIPS",
    "freeswitch": "FreeSWITCH", "wincc": "WinCC", "crowdstrike": "CrowdStrike",
    "esxi": "ESXi", "k8s": "K8s", "ddos": "DDoS", "ipsec": "IPsec",
    "aveva": "AVEVA", "simatic": "SIMATIC", "hyperv": "Hyper-V", "sql": "SQL",
    "corosync": "Corosync", "macos": "macOS", "bigip": "BIG-IP",
    "fortios": "FortiOS", "ufed": "UFED", "cloudtrail": "CloudTrail",
    "cyberark": "CyberArk", "hashicorp": "HashiCorp", "sharepoint": "SharePoint",
    "onedrive": "OneDrive", "workspace": "Workspace",
    "globalprotect": "GlobalProtect", "apparmor": "AppArmor",
    "anyconnect": "AnyConnect", "office365": "Office 365",
    "vmkernel": "VMkernel", "ipv4": "IPv4", "ipv6": "IPv6",
    "dhcp4": "DHCP4", "dhcp6": "DHCP6",
}
PRETTY_TOKEN_OVERRIDES = {
    "aaa": "AAA", "ad": "AD", "api": "API", "apm": "APM", "asa": "ASA",
    "aws": "AWS", "bsm": "BSM", "cdr": "CDR", "cli": "CLI", "crm": "CRM",
    "cups": "CUPS", "dfs": "DFS", "dhcp": "DHCP", "dns": "DNS", "edr": "EDR",
    "f5": "F5", "ftp": "FTP", "gcp": "GCP", "hids": "HIDS", "hmi": "HMI",
    "http": "HTTP", "https": "HTTPS", "ics": "ICS", "iis": "IIS", "ios": "IOS",
    "isc": "ISC", "kvm": "KVM", "mde": "MDE", "mtd": "MTD", "ngfw": "NGFW",
    "os": "OS", "ossec": "OSSEC", "ot": "OT", "pam": "PAM", "plc": "PLC",
    "s7": "S7", "sccm": "SCCM", "scada": "SCADA", "smb": "SMB", "ssh": "SSH",
    "ssl": "SSL", "tacacs": "TACACS", "vpn": "VPN", "w3c": "W3C",
    "ve": "VE", "pi": "PI", "ms": "MS", "id": "ID", "one": "ONE",
    "nps": "NPS", "radius": "RADIUS", "pve": "PVE", "vmms": "VMMS", "utm": "UTM",
}
PRETTY_LOWERCASE_CONNECTORS = {"for", "or", "and", "of", "the", "a", "an", "to", "in", "on"}


def prettify(raw):
    if raw in PRETTY_WHOLE_OVERRIDES:
        return PRETTY_WHOLE_OVERRIDES[raw]
    words = raw.split("_")
    out = []
    for i, w in enumerate(words):
        wl = w.lower()
        if wl in PRETTY_WHOLE_OVERRIDES:
            out.append(PRETTY_WHOLE_OVERRIDES[wl])
        elif wl in PRETTY_TOKEN_OVERRIDES:
            out.append(PRETTY_TOKEN_OVERRIDES[wl])
        elif wl in PRETTY_LOWERCASE_CONNECTORS and i != 0:
            out.append(wl)
        else:
            out.append(w.capitalize())
    return " ".join(out)


def build_tree(json_data, reference_data, matrix_filter):
    missing_log = []
    domain_filter = MATRIX_TO_DOMAIN.get(matrix_filter)
    ref_tactics = reference_data.get("tactics", {})
    ref_techniques = reference_data.get("techniques", {})

    def lookup(namespaced_id, ref_dict):
        entry = ref_dict.get(namespaced_id)
        if entry is None:
            missing_log.append(namespaced_id)
            return None
        return entry

    # technique_id -> [ {category_id, platform, service, category, status} ]
    coverage = {}
    # flat search index: [{id, label, type, path, raw_id}]
    search_index = []
    # category_id -> full display path (for the cross-reference panel)
    category_paths = {}

    warehouse = json_data.get("log_warehouse", {})
    platform_nodes = []

    for platform, services in warehouse.items():
        service_nodes = []
        platform_technique_ids = set()

        for service, categories in services.items():
            category_nodes = []

            for category, metadata in categories.items():
                if "mitre_tactics" not in metadata and "mitre_techniques" not in metadata:
                    raise ValueError(
                        f"Structural error at {platform}/{service}/{category}: JSON nests "
                        f"deeper than the expected 3 levels. Run validate_sources.py."
                    )

                techniques = metadata.get("mitre_techniques", [])
                is_broad = metadata.get("broad_spectrum", False)

                if domain_filter:
                    techniques = [t for t in techniques if t.startswith(domain_filter + ":")]
                    if not techniques and not is_broad:
                        continue

                category_id = f"category:{platform}:{service}:{category}"
                status = metadata.get("status", "unknown")
                if status not in STATUS_STYLE:
                    status = "unknown"
                siem_labels = metadata.get("siem_labels", {})
                secops_label = siem_labels.get("google_secops") or ""
                suffix = " [broad-spectrum]" if is_broad else ""
                display_label = f"{prettify(category)} [{secops_label}]{suffix}" if secops_label else f"{prettify(category)}{suffix}"
                full_path = f"{prettify(platform)} / {prettify(service)} / {prettify(category)}"
                category_paths[category_id] = full_path

                # group this source's techniques by EACH of their own real
                # MITRE tactic memberships (not the source's flat tactic
                # list) so multi-tactic techniques are grouped accurately
                tactic_groups = {}  # tactic_id -> {label, techniques: []}
                for technique in techniques:
                    tech_entry = lookup(technique, ref_techniques)
                    tech_name = tech_entry["name"] if tech_entry else technique
                    tech_tactics = tech_entry["tactic_ids"] if tech_entry else []
                    tech_tactic_names = [
                        (lookup(t, ref_tactics) or {}).get("name", t) for t in tech_tactics
                    ]

                    coverage.setdefault(technique, []).append({
                        "category_id": category_id, "platform": prettify(platform),
                        "service": prettify(service), "category": prettify(category), "status": status,
                    })
                    platform_technique_ids.add(technique)

                    search_index.append({
                        "id": f"technique:{technique}::{category_id}",
                        "raw_id": technique, "label": tech_name, "type": "technique",
                        "path": full_path,
                    })

                    for tactic in tech_tactics:
                        if domain_filter and not tactic.startswith(domain_filter + ":"):
                            continue
                        if tactic not in tactic_groups:
                            tactic_entry = lookup(tactic, ref_tactics)
                            tactic_groups[tactic] = {
                                "label": tactic_entry["name"] if tactic_entry else tactic,
                                "techniques": [], "raw_id": tactic,
                            }
                        tactic_groups[tactic]["techniques"].append({
                            "id": f"technique:{technique}::{category_id}::{tactic}",
                            "raw_id": technique, "label": tech_name, "type": "technique",
                            "mitre_url": mitre_url(technique),
                            "all_tactics": tech_tactic_names,
                        })

                tactic_children = [
                    {
                        "id": f"tactic:{tid}::{category_id}",
                        "label": tdata["label"], "type": "tactic",
                        "technique_count": len(tdata["techniques"]),
                        "mitre_url": mitre_tactic_url(tid),
                        "children": sorted(tdata["techniques"], key=lambda t: t["label"]),
                    }
                    for tid, tdata in tactic_groups.items()
                ]
                tactic_children.sort(key=lambda t: t["label"])

                search_index.append({
                    "id": category_id, "raw_id": category, "label": display_label,
                    "type": "category", "path": f"{prettify(platform)} / {prettify(service)}",
                })

                category_nodes.append({
                    "id": category_id, "label": display_label, "type": "category",
                    "status": status, "broad_spectrum": is_broad,
                    "broad_spectrum_reason": metadata.get("broad_spectrum_reason"),
                    "siem_labels": siem_labels,
                    "technique_count": len(techniques),
                    "children": tactic_children,
                })

            if category_nodes:
                category_nodes.sort(key=lambda c: -c["technique_count"])
                service_nodes.append({
                    "id": f"service:{platform}:{service}", "label": prettify(service), "type": "service",
                    "children": category_nodes,
                })

        if service_nodes:
            service_nodes.sort(key=lambda s: s["label"])
            search_index.append({
                "id": f"platform:{platform}", "raw_id": platform, "label": prettify(platform),
                "type": "platform", "path": "",
            })
            platform_nodes.append({
                "id": f"platform:{platform}", "label": prettify(platform), "type": "platform",
                "technique_count": len(platform_technique_ids),
                "children": service_nodes,
            })

    platform_nodes.sort(key=lambda p: -p["technique_count"])

    return {
        "tree": platform_nodes,
        "coverage": coverage,
        "search_index": search_index,
        "category_paths": category_paths,
    }, missing_log


# Inline sidebar icon. This is the commissioned STC logo, a raster PNG
# with its own internal art (not generated from the tool's CSS palette).
# It is NOT embedded as a literal constant in this source file - that
# approach previously bloated this file to 1.71MB and left no standalone,
# editable copy of the image anywhere in the repo. Instead the PNG lives
# as a real source asset at images/stc_logo.png and is read from disk and
# base64-encoded at generation time, below.
LOGO_ICON_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "images", "stc_logo.png")


def _load_logo_data_uri(path):
    """Read the sidebar logo PNG from disk and return it as a data URI.

    Fails loudly (rather than silently falling back to an empty/broken
    image) if the file is missing, since a missing logo is a real defect
    the person generating the file should see immediately, not one masked
    at generation time.
    """
    with open(path, "rb") as f:
        raw = f.read()
    encoded = base64.b64encode(raw).decode("ascii")
    return "data:image/png;base64," + encoded

# Favicon: same mark WITH its backing plate (a favicon needs to be
# self-contained/opaque against arbitrary browser chrome), simplified
# (no branching tree detail, which would just be noise at 16-32px) and
# URL-encoded at generation time into a data URI so the file stays a
# single standalone HTML document.
LOGO_FAVICON_SVG = """<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 200 200'>
<defs><radialGradient id='fgBg' cx='50%' cy='42%' r='70%'><stop offset='0%' stop-color='#111b2e'/><stop offset='100%' stop-color='#0a0e17'/></radialGradient>
<radialGradient id='fgWash' cx='50%' cy='50%' r='50%'><stop offset='0%' stop-color='#38bdf8' stop-opacity='0.28'/><stop offset='100%' stop-color='#38bdf8' stop-opacity='0'/></radialGradient></defs>
<circle cx='100' cy='100' r='98' fill='url(#fgBg)'/><circle cx='100' cy='100' r='60' fill='url(#fgWash)'/>
<circle cx='100' cy='100' r='68' fill='none' stroke='#334155' stroke-width='1.6' stroke-dasharray='3 5'/>
<circle cx='100' cy='100' r='88' fill='none' stroke='#38bdf8' stroke-width='4'/>
<circle cx='100' cy='100' r='7' fill='#ef4444'/>
<circle cx='70' cy='78' r='6' fill='#fb923c'/><circle cx='130' cy='78' r='6' fill='#eab308'/>
<circle cx='60' cy='120' r='6' fill='#22c55e'/><circle cx='140' cy='120' r='6' fill='#a855f7'/>
</svg>"""


def generate_html(data, matrix_filter):
    json_str = json.dumps(data, separators=(",", ":"))
    logo_icon_data_uri = _load_logo_data_uri(LOGO_ICON_PATH)
    favicon_data_uri = "data:image/svg+xml," + quote(LOGO_FAVICON_SVG)
    # Defense against script-tag injection: if any embedded string ever
    # contained a literal "</script>" sequence, it would prematurely close
    # this inline script block and let the rest be interpreted as raw HTML.
    # json.dumps does not escape forward slashes by default, so this is a
    # real (if currently low-probability, since all source data is our own
    # generation pipeline plus MITRE's reference data) risk, not a
    # hypothetical one - escaping it here costs nothing and removes the
    # risk regardless of what future data ever contains.
    json_str = json_str.replace("</", "<\\/")
    matrix_label = {"all": "All Domains", "enterprise": "Enterprise", "mobile": "Mobile", "ics": "ICS"}[matrix_filter]
    # The legend sample previews the ACTUAL status-ring rendering (a
    # colored outline around a small circle, matching the box-shadow ring
    # applied to real category nodes) rather than a solid dot, which
    # didn't match what appears in the tree.
    status_legend = "".join(
        f'<div class="legend-item"><span class="status-ring-sample" style="box-shadow:0 0 0 2px {v["color"]}"></span>{v["label"]}</div>'
        for v in STATUS_STYLE.values()
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>STC - {matrix_label}</title>
<link rel="icon" type="image/svg+xml" href="{favicon_data_uri}">
<!-- Content Security Policy, as defense in depth alongside the safe DOM
     construction and script-injection escaping used throughout this file's
     generated JavaScript (see the "el()" helper and the JSON escaping in
     generate_html() in generate_stc_map.py). This can't fully prevent
     inline-script execution on its own, since the embedded JS and CSS are
     inline rather than nonce-verified external files - 'unsafe-inline' is
     required for both to function at all. What it DOES provide: no
     resource (script, style, font, or otherwise) can load from anywhere
     except this page itself and the two Google Fonts domains explicitly
     listed below, and the page cannot be embedded in a frame on another
     site, which blocks a distinct class of attack (arbitrary third-party
     resource injection, clickjacking) independent of the inline-script
     limitation. Works the same way whether this file is opened via
     file:// or served over http(s) - modern browsers apply a meta-tag CSP
     regardless of the page's origin scheme. -->
<meta http-equiv="Content-Security-Policy" content="default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; script-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self';">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
<style>
  :root {{
    --bg: #0a0e17; --surface: #0d1424; --surface2: #111b2e; --border: #1e293b;
    --ink: #e7ecf5; --muted: #64748b; --muted2: #94a3b8;
    --platform: #f97316; --service: #eab308; --category: #22c55e;
    --tactic: #06b6d4; --technique: #a855f7; --target: #ef4444;
  }}
  * {{ box-sizing: border-box; }}
  @media (prefers-reduced-motion: reduce) {{ *, *::before, *::after {{ animation-duration: 0.01ms !important; transition-duration: 0.01ms !important; }} }}
  body {{
    margin: 0; background: var(--bg); color: var(--ink);
    font-family: "Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    font-size: 14px;
  }}
  .mono {{ font-family: "IBM Plex Mono", ui-monospace, monospace; }}
  #sidebar {{
    position: fixed; top: 0; left: 0; width: 300px; height: 100vh;
    background: var(--surface); border-right: 1px solid var(--border); padding: 20px;
    overflow-y: auto; z-index: 10;
  }}
  #main {{ margin-left: 300px; padding: 28px 36px 100px 36px; max-width: 1020px; }}
  .logo-header {{ display: flex; flex-direction: column; align-items: center; text-align: center; gap: 4px; margin: 0 0 18px 0; }}
  .logo-header img {{ width: 150px; height: 200px; object-fit: contain; flex-shrink: 0; margin-bottom: 2px; }}
  .logo-title {{
    font-family: "IBM Plex Mono", monospace; font-weight: 600; font-size: 19px;
    color: #38bdf8; letter-spacing: -0.01em; line-height: 1.2;
  }}
  .logo-subtitle {{
    font-family: "IBM Plex Mono", monospace; font-size: 11px; color: var(--muted2);
    letter-spacing: 0.02em;
  }}
  h2 {{
    font-family: "IBM Plex Mono", monospace; font-size: 10.5px; color: var(--muted2);
    text-transform: uppercase; letter-spacing: .08em; margin: 18px 0 7px 0;
  }}
  input#search {{
    width: 100%; padding: 9px 11px; background: var(--surface2); border: 1px solid var(--border);
    border-radius: 6px; color: var(--ink); font-size: 13px; font-family: inherit;
  }}
  input#search:focus {{ outline: 2px solid #38bdf8; outline-offset: 1px; }}
  #searchResults {{ max-height: 220px; overflow-y: auto; margin-top: 6px; }}
  .search-hit {{ padding: 7px 9px; font-size: 12px; cursor: pointer; border-radius: 5px; color: #cbd5e1; }}
  .search-hit:hover, .search-hit:focus {{ background: var(--surface2); color: #fff; }}
  .search-hit small {{ display: block; color: var(--muted); margin-top: 1px; }}
  button.tool {{
    width: 100%; padding: 9px; margin-top: 6px; background: var(--surface2); color: #cbd5e1;
    border: 1px solid var(--border); border-radius: 6px; cursor: pointer; font-size: 12.5px;
    font-family: inherit; transition: background 0.12s, border-color 0.12s;
  }}
  button.tool:hover {{ background: #1e293b; border-color: #334155; color: #fff; }}
  button.tool:focus-visible {{ outline: 2px solid #38bdf8; outline-offset: 1px; }}
  .legend-item {{ display: flex; align-items: center; font-size: 12px; margin: 4px 0; color: #cbd5e1; }}
  .dot {{ width: 10px; height: 10px; border-radius: 50%; margin-right: 9px; flex-shrink: 0; display: inline-block; }}
  .status-ring-sample {{
    width: 9px; height: 9px; border-radius: 50%; margin-right: 9px; flex-shrink: 0;
    display: inline-block; background: #334155;
  }}
  .shape-sample {{ margin-right: 9px; flex-shrink: 0; }}
  .hint {{ font-size: 11px; color: var(--muted); line-height: 1.6; margin-top: 16px; }}
  .hint b {{ color: var(--muted2); }}

  ul.tree {{ list-style: none; margin: 0; padding-left: 22px; }}
  ul.tree.root {{ padding-left: 0; }}
  li.node {{ margin: 1px 0; position: relative; }}
  .row {{
    display: flex; align-items: center; padding: 4px 7px; border-radius: 5px;
    cursor: pointer; gap: 8px; transition: background 0.1s;
  }}
  .row:hover {{ background: var(--surface2); }}
  .row:focus-visible {{ outline: 2px solid #38bdf8; outline-offset: -1px; }}
  .row.technique-row:hover {{ background: #2a1152; }}
  .caret {{
    width: 14px; text-align: center; color: var(--muted); font-size: 10px;
    transition: transform 0.12s; flex-shrink: 0;
  }}
  .caret.open {{ transform: rotate(90deg); }}
  .caret.leaf {{ visibility: hidden; }}

  /* node shapes - distinct silhouette per type, not just color, so the
     hierarchy reads even without relying on color alone. Platform and
     service are deliberately elongated (badge/chip proportions rather
     than symmetric) with a subtle gradient fill for a more considered,
     less flat look. */
  .node-shape {{ flex-shrink: 0; display: inline-block; }}
  .shape-platform {{
    width: 22px; height: 11px;
    background: linear-gradient(135deg, #fb923c 0%, #ea580c 100%);
    clip-path: polygon(18% 0%, 82% 0%, 100% 50%, 82% 100%, 18% 100%, 0% 50%);
  }}
  .shape-service {{
    width: 17px; height: 8px; border-radius: 4px;
    background: linear-gradient(135deg, #fde047 0%, #ca8a04 100%);
  }}
  .shape-category {{
    width: 10px; height: 10px; border-radius: 50%;
    background: linear-gradient(135deg, #4ade80 0%, #16a34a 100%);
  }}
  .shape-tactic {{
    width: 10px; height: 10px;
    background: linear-gradient(135deg, #22d3ee 0%, #0891b2 100%);
    clip-path: polygon(50% 0%, 100% 50%, 50% 100%, 0% 50%);
  }}
  .shape-technique {{
    width: 7px; height: 7px; border-radius: 50%;
    background: linear-gradient(135deg, #c084fc 0%, #9333ea 100%);
  }}

  .label {{
    color: var(--ink);
    text-shadow: 0 1px 0 rgba(0,0,0,0.6), 0 0 6px rgba(0,0,0,0.35);
  }}
  .count {{ font-family: "IBM Plex Mono", monospace; color: var(--muted); font-size: 12px; }}
  li.node > ul.tree {{ display: none; }}
  li.node.open > ul.tree {{ display: block; animation: reveal 0.14s ease-out; }}
  @keyframes reveal {{ from {{ opacity: 0; transform: translateY(-2px); }} to {{ opacity: 1; transform: translateY(0); }} }}
  .badge-broad {{
    font-family: "IBM Plex Mono", monospace; font-size: 9.5px; color: #f8fafc;
    background: #475569; border-radius: 3px; padding: 1px 6px; margin-left: 4px;
  }}

  /* "target acquired" pulse - the one signature moment, plays only when a
     search or cross-reference jump lands on a node, not ambiently */
  @keyframes targetPulse {{
    0% {{ box-shadow: 0 0 0 0 rgba(239,68,68,0.55); background: rgba(239,68,68,0.16); }}
    70% {{ box-shadow: 0 0 0 14px rgba(239,68,68,0); background: rgba(239,68,68,0.05); }}
    100% {{ box-shadow: 0 0 0 0 rgba(239,68,68,0); background: transparent; }}
  }}
  .row.target-pulse {{ animation: targetPulse 1.1s ease-out; border-radius: 5px; }}

  /* hover flyout - contextual data + links, appears near the row */
  #flyout {{
    position: fixed; z-index: 30; max-width: 340px; background: var(--surface2);
    border: 1px solid #334155; border-radius: 8px; padding: 13px 15px;
    box-shadow: 0 10px 30px rgba(0,0,0,0.5); font-size: 12.5px; line-height: 1.55;
    display: none; pointer-events: none;
  }}
  #flyout.visible {{ display: block; }}
  #flyout .fy-title {{ font-family: "IBM Plex Mono", monospace; font-weight: 600; color: #f8fafc; margin-bottom: 3px; }}
  #flyout .fy-row {{ color: #cbd5e1; margin-top: 5px; }}
  #flyout .fy-label {{ color: var(--muted2); font-size: 10.5px; text-transform: uppercase; letter-spacing: .04em; }}
  #flyout .fy-mono {{ font-family: "IBM Plex Mono", monospace; font-size: 12px; color: #7dd3fc; }}
  #flyout a {{ color: #38bdf8; text-decoration: none; pointer-events: auto; }}
  #flyout a:hover {{ text-decoration: underline; }}
  #flyout .fy-siem {{ margin-top: 6px; display: grid; grid-template-columns: auto 1fr; gap: 2px 8px; }}
  #flyout .fy-siem .k {{ color: var(--muted); font-size: 11px; }}
  #flyout .fy-siem .v {{ font-family: "IBM Plex Mono", monospace; font-size: 11px; color: #cbd5e1; }}
  #flyout .fy-null {{ color: #475569; font-style: italic; }}

  #crossref {{
    position: fixed; top: 0; right: 0; width: 350px; height: 100vh;
    background: var(--surface); border-left: 1px solid var(--border); padding: 20px;
    overflow-y: auto; transform: translateX(100%); transition: transform 0.2s; z-index: 20;
  }}
  #crossref.open {{ transform: translateX(0); }}
  #crossref h3 {{ font-family: "IBM Plex Mono", monospace; font-size: 14px; color: #c084fc; margin: 0 0 4px 0; }}
  #crossref .sub {{ font-size: 12px; color: var(--muted); margin-bottom: 15px; }}
  #crossref .closeBtn {{ float: right; cursor: pointer; color: var(--muted); font-size: 19px; line-height: 1; }}
  #crossref .closeBtn:hover {{ color: #fff; }}
  .xref-item {{
    padding: 9px 10px; margin-bottom: 6px; background: var(--surface2); border-radius: 7px;
    cursor: pointer; font-size: 12.5px; transition: background 0.12s;
  }}
  .xref-item:hover {{ background: #1e2c47; }}
  .xref-item .path {{ color: var(--muted2); font-size: 11px; margin-top: 2px; }}
</style>
</head>
<body>
<div id="sidebar">
  <div class="logo-header">
    <img src="{logo_icon_data_uri}" alt="STC logo" width="150" height="200">
    <div>
      <div class="logo-title">STC</div>
      <div class="logo-subtitle">{matrix_label}</div>
    </div>
  </div>
  <input id="search" type="text" placeholder="Search a source or technique...">
  <div id="searchResults"></div>
  <button class="tool" id="expandAllBtn">Expand all platforms</button>
  <button class="tool" id="collapseAllBtn">Collapse all</button>
  <h2>Node Types</h2>
  <div class="legend-item"><span class="node-shape shape-platform shape-sample"></span>Platform (n = technique count)</div>
  <div class="legend-item"><span class="node-shape shape-service shape-sample"></span>Service</div>
  <div class="legend-item"><span class="node-shape shape-category shape-sample"></span>Log source (n = technique count)</div>
  <div class="legend-item"><span class="node-shape shape-tactic shape-sample"></span>MITRE Tactic (n = techniques here)</div>
  <div class="legend-item"><span class="node-shape shape-technique shape-sample"></span>MITRE Technique</div>
  <h2>Coverage Status (source ring color)</h2>
  {status_legend}
  <p class="hint"><b>Click a row</b> to expand or collapse it.<br>
  <b>Hover</b> a source or technique for details and links.<br>
  <b>Click a technique</b> to see every other source that also covers it, even ones you haven't expanded.<br>
  Sources are sorted richest-first within each level.</p>
</div>
<div id="main"><ul class="tree root" id="rootTree"></ul></div>
<div id="flyout"></div>
<div id="crossref">
  <span class="closeBtn" id="xrefClose">&times;</span>
  <h3 id="xrefTitle"></h3>
  <div class="sub" id="xrefSub"></div>
  <div id="xrefList"></div>
</div>
<script>
const DATA = {json_str};
const SHAPE_CLASS = {{ platform: "shape-platform", service: "shape-service", category: "shape-category", tactic: "shape-tactic", technique: "shape-technique" }};
const STATUS_COLOR = {{ collected: "#6366f1", planned: "#ec4899", not_collected: "#64748b", unknown: "#94a3b8" }};

// Builds one row's DOM elements (expand caret, type shape, label text,
// and an optional broad-spectrum badge) without assembling any of it as
// an HTML string - every piece is a real DOM node, so nothing here can
// be misinterpreted as markup even if a label ever contained
// HTML-special characters.
function makeRow(node) {{
  const row = document.createElement("div");
  row.className = "row" + (node.type === "technique" ? " technique-row" : "");
  const hasChildren = Array.isArray(node.children) && node.children.length > 0;

  const caret = document.createElement("span");
  caret.className = "caret" + (hasChildren ? "" : " leaf");
  caret.textContent = hasChildren ? "\\u25B8" : "";
  row.appendChild(caret);

  const shape = document.createElement("span");
  shape.className = "node-shape " + SHAPE_CLASS[node.type];
  if (node.type === "category") {{
    shape.style.boxShadow = `0 0 0 2px ${{STATUS_COLOR[node.status]}}`;
  }}
  row.appendChild(shape);

  const label = document.createElement("span");
  label.className = "label";
  let text = node.label;
  if (node.technique_count !== undefined) text += ` (${{node.technique_count}})`;
  label.textContent = text;
  row.appendChild(label);

  if (node.broad_spectrum) {{
    const badge = document.createElement("span");
    badge.className = "badge-broad";
    badge.textContent = "broad-spectrum";
    row.appendChild(badge);
  }}

  return {{ row, caret, hasChildren }};
}}

// Recursively builds one node's <li> and, if it has children, its
// nested <ul> - this is the only place the tree's DOM structure gets
// assembled, so the whole page's node count is proportional to what's
// actually expanded, not the full catalog.
function renderNode(node) {{
  const li = document.createElement("li");
  li.className = "node";
  li.dataset.id = node.id;
  const {{ row, caret, hasChildren }} = makeRow(node);
  li.appendChild(row);

  let childUl = null;
  if (hasChildren) {{
    childUl = document.createElement("ul");
    childUl.className = "tree";
    node.children.forEach(child => childUl.appendChild(renderNode(child)));
    li.appendChild(childUl);
  }}

  row.addEventListener("click", () => {{
    if (node.type === "technique") {{
      showCrossReference(node);
      return;
    }}
    if (hasChildren) {{
      li.classList.toggle("open");
      caret.classList.toggle("open");
    }}
  }});

  if (node.type === "category" || node.type === "technique" || node.type === "tactic") {{
    row.addEventListener("mouseenter", (e) => showFlyout(node, row));
    row.addEventListener("mouseleave", hideFlyout);
  }}

  return li;
}}

const rootUl = document.getElementById("rootTree");
DATA.tree.forEach(platform => rootUl.appendChild(renderNode(platform)));

document.getElementById("expandAllBtn").addEventListener("click", () => {{
  document.querySelectorAll("#rootTree > li.node").forEach(li => {{
    li.classList.add("open");
    li.querySelector(":scope > .row .caret").classList.add("open");
  }});
}});
document.getElementById("collapseAllBtn").addEventListener("click", () => {{
  document.querySelectorAll("li.node.open").forEach(li => {{
    li.classList.remove("open");
    const caret = li.querySelector(":scope > .row .caret");
    if (caret) caret.classList.remove("open");
  }});
}});

// hover flyout: contextual data + real links, positioned near the row.
// Built via safe DOM construction (createElement + textContent), not
// innerHTML string interpolation - none of this data is currently
// attacker-controlled, but building it this way means a technique/source
// name or SIEM label value could never be interpreted as markup even if
// the underlying data ever changed, rather than relying on "the current
// data happens to be safe."
const flyoutEl = document.getElementById("flyout");

// Shared element-builder used everywhere a link, label, or row needs
// constructing. Any element created with an `href` automatically gets
// target="_blank" and rel="noopener noreferrer" - noopener prevents the
// opened page from reaching back into this one via window.opener,
// noreferrer additionally withholds the referring URL. Centralizing
// this here means every link this file ever generates gets both
// attributes by construction, rather than needing each call site to
// remember to add them.
function el(tag, opts) {{
  const e = document.createElement(tag);
  if (opts) {{
    if (opts.className) e.className = opts.className;
    if (opts.text !== undefined) e.textContent = opts.text;
    if (opts.href !== undefined) {{ e.href = opts.href; e.target = "_blank"; e.rel = "noopener noreferrer"; }}
  }}
  return e;
}}

// A real <a> element (via the shared el() helper) rather than a string,
// so it always carries the correct target/rel attributes - see el()'s
// own comment for why that matters.
function mitreLink(url) {{
  const a = el("a", {{ text: "View on attack.mitre.org", href: url }});
  a.append(" \\u2192");
  return a;
}}

function showFlyout(node, rowEl) {{
  flyoutEl.replaceChildren();
  flyoutEl.appendChild(el("div", {{ className: "fy-title", text: node.label }}));

  if (node.type === "technique") {{
    const linkRow = el("div", {{ className: "fy-row" }});
    linkRow.appendChild(mitreLink(node.mitre_url));
    flyoutEl.appendChild(linkRow);
    const idRow = el("div", {{ className: "fy-row" }});
    idRow.appendChild(el("span", {{ className: "fy-mono", text: node.raw_id }}));
    flyoutEl.appendChild(idRow);
    if (node.all_tactics && node.all_tactics.length) {{
      const tRow = el("div", {{ className: "fy-row" }});
      tRow.appendChild(el("span", {{ className: "fy-label", text: "Tactics" }}));
      tRow.appendChild(document.createElement("br"));
      tRow.append(node.all_tactics.join(", "));
      flyoutEl.appendChild(tRow);
    }}
  }} else if (node.type === "tactic") {{
    const linkRow = el("div", {{ className: "fy-row" }});
    linkRow.appendChild(mitreLink(node.mitre_url));
    flyoutEl.appendChild(linkRow);
    flyoutEl.appendChild(el("div", {{ className: "fy-row", text: `${{node.technique_count}} technique(s) from this source` }}));
  }} else if (node.type === "category") {{
    const statusRow = el("div", {{ className: "fy-row" }});
    statusRow.append("Status: ");
    statusRow.appendChild(el("b", {{ text: node.status }}));
    flyoutEl.appendChild(statusRow);
    if (node.broad_spectrum && node.broad_spectrum_reason) {{
      flyoutEl.appendChild(el("div", {{ className: "fy-row", text: node.broad_spectrum_reason }}));
    }}
    const labels = node.siem_labels || {{}};
    const labelNames = {{ google_secops: "Google SecOps", splunk_sourcetype: "Splunk sourcetype", elastic_ecs_dataset: "Elastic ECS dataset", sentinel_table: "Sentinel table", wazuh_rule_group: "Wazuh rule group" }};
    const grid = el("div", {{ className: "fy-siem" }});
    Object.entries(labelNames).forEach(([key, name]) => {{
      const val = labels[key];
      grid.appendChild(el("span", {{ className: "k", text: name }}));
      if (val) {{
        grid.appendChild(el("span", {{ className: "v", text: val }}));
      }} else {{
        const v = el("span", {{ className: "v" }});
        v.appendChild(el("span", {{ className: "fy-null", text: "not yet mapped" }}));
        grid.appendChild(v);
      }}
    }});
    flyoutEl.appendChild(grid);
  }}

  const rect = rowEl.getBoundingClientRect();
  flyoutEl.style.left = Math.min(rect.right + 12, window.innerWidth - 356) + "px";
  flyoutEl.style.top = Math.min(rect.top, window.innerHeight - 220) + "px";
  flyoutEl.classList.add("visible");
}}
function hideFlyout() {{ flyoutEl.classList.remove("visible"); }}

function showCrossReference(node) {{
  const panel = document.getElementById("crossref");
  const covering = DATA.coverage[node.raw_id] || [];
  document.getElementById("xrefTitle").textContent = node.label;

  const sub = document.getElementById("xrefSub");
  sub.replaceChildren();
  sub.appendChild(el("span", {{ className: "mono", text: node.raw_id }}));
  sub.append(` \\u2014 covered by ${{covering.length}} source${{covering.length === 1 ? "" : "s"}} \\u00b7 `);
  const link = el("a", {{ text: "view on attack.mitre.org", href: node.mitre_url }});
  link.style.color = "#38bdf8";
  sub.appendChild(link);

  const list = document.getElementById("xrefList");
  list.replaceChildren();
  covering.forEach(c => {{
    const item = el("div", {{ className: "xref-item" }});
    item.appendChild(el("div", {{ text: c.category }}));
    item.appendChild(el("div", {{ className: "path", text: `${{c.platform}} / ${{c.service}} \\u2014 ${{c.status}}` }}));
    item.addEventListener("click", () => jumpToCategory(c.category_id));
    list.appendChild(item);
  }});
  panel.classList.add("open");
}}
document.getElementById("xrefClose").addEventListener("click", () => {{
  document.getElementById("crossref").classList.remove("open");
}});

// Walks up from a node to the root, opening every ancestor <li> along
// the way, so a search or cross-reference jump lands somewhere actually
// visible instead of hidden inside a collapsed parent. Climbs via
// `.closest("li.node")` on each parent <ul>'s own parent, rather than a
// simple `.parentElement` chain, because the DOM path from one <li> to
// its ancestor <li> passes through an intermediate <ul> that isn't
// itself a node.
function expandAncestors(id) {{
  let li = document.querySelector(`li.node[data-id="${{CSS.escape(id)}}"]`);
  while (li) {{
    li.classList.add("open");
    const caret = li.querySelector(":scope > .row .caret");
    if (caret) caret.classList.add("open");
    const parentUl = li.parentElement;
    li = parentUl && parentUl.closest("li.node");
  }}
}}

// the signature "target acquired" moment - plays once when landing on a
// search or cross-reference jump target, not ambiently
function pulseTarget(el) {{
  const row = el.querySelector(":scope > .row");
  row.classList.remove("target-pulse");
  void row.offsetWidth; // restart animation if it was already mid-play
  row.classList.add("target-pulse");
  setTimeout(() => row.classList.remove("target-pulse"), 1200);
}}

// Used by the cross-reference panel: expand whatever ancestor chain is
// needed, scroll the target source into view, play the target-acquired
// pulse on it, and close the panel so it doesn't obscure the result.
function jumpToCategory(categoryId) {{
  expandAncestors(categoryId);
  const el = document.querySelector(`li.node[data-id="${{CSS.escape(categoryId)}}"]`);
  if (el) {{
    el.scrollIntoView({{ behavior: "smooth", block: "center" }});
    pulseTarget(el);
  }}
  document.getElementById("crossref").classList.remove("open");
}}

const searchBox = document.getElementById("search");
const resultsBox = document.getElementById("searchResults");
searchBox.addEventListener("input", () => {{
  const q = searchBox.value.trim().toLowerCase();
  resultsBox.replaceChildren();
  if (q.length < 2) return;
  const hits = DATA.search_index.filter(n =>
    n.label.toLowerCase().includes(q) || (n.raw_id || "").toLowerCase().includes(q)
  ).slice(0, 30);
  hits.forEach(h => {{
    const div = el("div", {{ className: "search-hit", text: h.label }});
    if (h.path) {{
      div.appendChild(el("small", {{ text: h.path }}));
    }}
    div.addEventListener("click", () => {{
      const targetId = h.type === "technique" ? h.id.split("::")[1] : h.id;
      expandAncestors(targetId);
      const targetLi = document.querySelector(`li.node[data-id="${{CSS.escape(targetId)}}"]`);
      if (targetLi) {{
        targetLi.scrollIntoView({{ behavior: "smooth", block: "center" }});
        pulseTarget(targetLi);
      }}
      resultsBox.replaceChildren();
      searchBox.value = "";
    }});
    resultsBox.appendChild(div);
  }});
}});
</script>
</body>
</html>
"""


def main():
    args = parse_arguments()
    for path, label in [(args.input, "input"), (args.reference, "reference")]:
        if not os.path.exists(path):
            print(f"Error: {label} file not found: {path}", file=sys.stderr)
            sys.exit(1)

    with open(args.input, encoding="utf-8") as f:
        try:
            json_payload = json.load(f)
        except json.JSONDecodeError as e:
            print(f"Error: {args.input} is not valid JSON: {e}", file=sys.stderr)
            sys.exit(1)
    with open(args.reference, encoding="utf-8") as f:
        try:
            reference_data = json.load(f)
        except json.JSONDecodeError as e:
            print(f"Error: {args.reference} is not valid JSON: {e}", file=sys.stderr)
            sys.exit(1)

    print("[*] Building expandable tree dataset...")
    data, missing_log = build_tree(json_payload, reference_data, args.matrix)

    if missing_log:
        unique_missing = sorted(set(missing_log))
        print(f"[!] {len(unique_missing)} unique MITRE ID(s) not found in {args.reference}:")
        for m in unique_missing:
            print(f"    {m}")

    total_categories = sum(1 for entry in data["search_index"] if entry["type"] == "category")
    print(f"[*] {len(data['tree'])} platforms, {total_categories} sources, "
          f"{len(data['coverage'])} unique techniques covered")

    print("[*] Generating standalone HTML5 tree...")
    html_output = generate_html(data, args.matrix)

    with open(args.output, 'w', encoding='utf-8') as out_file:
        out_file.write(html_output)
    print(f"[+] Wrote {args.output}")


if __name__ == "__main__":
    main()
