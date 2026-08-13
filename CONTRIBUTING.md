# Contributing to STC

Thank you for considering a contribution. This document covers what a
good contribution looks like, how to submit one, and what happens after
you do.

## Before you contribute

STC requires a signed Contributor License Agreement (CLA) before any
contribution can be merged. Read [`CLA.md`](CLA.md) first. It explains
why the project needs this and what you're agreeing to. State your
agreement in your first pull request, as described at the end of that
document.

## What STC needs

- New log source mappings, for products or platforms not yet in
  `data_sources.json`.
- Corrections to existing mappings, including techniques that are
  claimed but shouldn't be, or missing techniques a source genuinely
  supports.
- SIEM field mappings (Splunk sourcetype, Elastic ECS dataset, and so
  on) for sources that currently show them as unmapped.
- Coverage of MITRE ATT&CK versions newer than the one
  `mitre_reference.json` currently reflects.
- Corrections to `out_of_scope_techniques.json` or `research_needed.json`,
  if you have evidence that changes a prior decision.
- Improvements to `generate_stc_map.py`, `validate_sources.py`, or the
  other tooling.

## The evidence standard

This is the part that matters most. A coverage catalog is only useful if
its claims are true, so every technique mapping needs real evidence
behind it, not a plausible guess.

**Acceptable evidence:**

- A vendor's official documentation stating what a log or event
  contains.
- A specific, named event ID, field, or log line that demonstrates the
  claim.
- Independent confirmation from more than one credible source, when a
  single source seems thin.

**Not acceptable:**

- "This product probably logs that" without a citation.
- Assuming a capability exists because a similar product has it. Two
  products in the same category often behave differently. Verify each
  one on its own.
- Copying a mapping from another coverage framework without checking
  it against the source's actual documented behavior.

If you're not confident in a mapping, that's fine. Add it to
`research_needed.json` instead of `data_sources.json`, with what would
need to be verified to resolve it. A documented open question is more
useful than an unverified claim presented as fact.

The same standard applies to marking a technique out of scope. Add it
to `out_of_scope_techniques.json` with a specific reason, not a generic
one. "Not observable in any log source, since it describes an
attacker's own passive network sniffing" is a reason. "Hard to detect"
is not.

## Submitting a change

1. Edit `data_sources.json` directly. Keep the existing structure:
   `platform → service → log source`, with `mitre_tactics`,
   `mitre_techniques`, `siem_labels`, and `status` fields. See
   [`docs/schema.md`](docs/schema.md) for the full field reference.
2. Run the validator:

   ```bash
   python3 validate_sources.py
   ```

   This confirms every technique ID you added resolves against
   `mitre_reference.json`. Fix any error it reports before you continue.
3. If your change affects overall coverage, regenerate the report to
   confirm the numbers look right:

   ```bash
   python3 coverage_gap_report.py
   ```
4. Regenerate the mind map so it reflects your change:

   ```bash
   python3 generate_stc_map.py -i data_sources.json -r mitre_reference.json -o stc_map.html --matrix all
   ```
5. Open a pull request. In the description, include:
   - What you added, changed, or removed, and why.
   - The evidence behind each new or changed mapping (a link to
     documentation, a specific event ID, and so on).
   - Confirmation that you've read and agree to the CLA.

## Reporting a problem without submitting a fix

If you've found an incorrect mapping but don't have time to fix it
yourself, open an issue. Include the source, the technique ID, and why
you believe the mapping is wrong. This is genuinely useful on its own,
even without a pull request attached.

## Adding a new MITRE domain or updating the reference data

`mitre_reference.json` is generated from MITRE's official STIX data
using `ingest_mitre_stix.py`. If you're updating it for a new ATT&CK
version, download the current STIX bundles with `fetch_reference.sh`
(requires network access), then run `ingest_mitre_stix.py` against the
downloaded files rather than editing `mitre_reference.json` by hand.
Then run `test_ingest_mitre.py` to confirm the result has the expected
shape.

## Code style

Keep changes to the Python tooling consistent with the existing style:
standard library only, no external dependencies beyond what's already
imported, and clear variable names over clever ones. If you're adding a
new script, explain what it does and why it's needed in the pull
request description.

## Questions

Open an issue if anything in this document is unclear, or if you're not
sure whether something you want to contribute fits the project's scope.
