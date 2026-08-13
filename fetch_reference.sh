#!/usr/bin/env bash
# Downloads the current MITRE ATT&CK STIX bundles for all three domains.
# Source repo: https://github.com/mitre-attack/attack-stix-data
# Run this somewhere with network access, then point ingest_mitre_stix.py at
# the downloaded files.
set -euo pipefail

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    echo "Usage: $(basename "$0")"
    echo ""
    echo "Downloads the current MITRE ATT&CK STIX bundles (Enterprise, Mobile,"
    echo "and ICS) from the official mitre-attack/attack-stix-data repository"
    echo "into ./mitre_stix_data/, then prints the ingest_mitre_stix.py command"
    echo "to build mitre_reference.json from them."
    echo ""
    echo "Takes no arguments. Requires network access to raw.githubusercontent.com."
    exit 0
fi

BASE_URL="https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master"
OUT_DIR="$(dirname "$0")/mitre_stix_data"
mkdir -p "$OUT_DIR"

for domain in enterprise-attack mobile-attack ics-attack; do
    echo "Downloading ${domain}..."
    curl -sSL "${BASE_URL}/${domain}/${domain}.json" -o "${OUT_DIR}/${domain}.json"
done

echo ""
echo "Done. Next:"
echo "  python3 ingest_mitre_stix.py \\"
echo "    --enterprise ${OUT_DIR}/enterprise-attack.json \\"
echo "    --mobile ${OUT_DIR}/mobile-attack.json \\"
echo "    --ics ${OUT_DIR}/ics-attack.json \\"
echo "    -o mitre_reference.json"
echo ""
echo "Then sanity-check the printed tactic/technique counts against MITRE's"
echo "published totals at https://attack.mitre.org/resources/updates/"
echo "(as of ATT&CK 19.1: Enterprise 15 tactics/222 techniques/475 sub-techniques;"
echo "Mobile 12/77/47; ICS 12/79/18 - re-check that page since these numbers"
echo "change with each quarterly ATT&CK release)."
