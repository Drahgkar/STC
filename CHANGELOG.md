# Changelog

All notable changes to STC are documented here. This changelog starts
from the project's first public release. Earlier development history
lives in the git log, not in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/), and
this project uses [Semantic Versioning](https://semver.org/) for
tagged releases.

## [Unreleased]

### Added

- Initial public release of the coverage catalog: 152 log sources
  across 40 platforms, mapped to 712 of 918 MITRE ATT&CK techniques
  (98.6% of in-scope techniques) across the Enterprise, Mobile, and ICS
  domains.
- `stc_map.html`, an expandable-tree visualization of the
  catalog with search, a technique-to-source cross-reference panel,
  links to the official MITRE ATT&CK page for each technique, the STC
  logo embedded inline in the sidebar, and a Content Security Policy
  restricting it to loading resources only from itself and its two
  Google Fonts domains.
- `generate_stc_map.py`, `validate_sources.py`, and
  `coverage_gap_report.py` for regenerating and checking the catalog,
  each with per-argument `--help` text and clean error messages for
  missing files or invalid JSON.
- `ingest_mitre_stix.py` for rebuilding `mitre_reference.json` from
  MITRE's official STIX data, and `fetch_reference.sh` for downloading
  the STIX bundles it reads.
- `out_of_scope_techniques.json`, documenting 196 techniques
  deliberately excluded from coverage, each with a specific reason.
- `research_needed.json`, tracking open questions the catalog hasn't
  resolved yet.
- Dual licensing under AGPLv3 and a separate commercial license, with a
  Contributor License Agreement covering community contributions.
