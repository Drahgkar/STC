# The mind map tool

`stc_map.html` is a standalone, interactive view of
`data_sources.json`. It needs no server, no install step, and no
internet connection beyond loading its typeface from Google Fonts. Open
the file in a browser.

## Why a tree, not a graph

Earlier versions of this tool used a force-directed radial graph.
That approach broke down at the catalog's current scale: with 152
sources and over 700 covered techniques, a graph has a fixed amount of
space to lay everything out in, and expanding more than a couple of
branches at once produced overlapping nodes and crossing lines no
amount of tuning fully resolved.

An expandable tree doesn't have that ceiling. It grows in one
direction on a scrollable page, so expanding ten branches at once just
means more scrolling, not more crossing lines. It's also deterministic:
given which nodes are expanded, there's exactly one correct layout,
computed directly, with no physics simulation to settle.

## Navigating the tree

The tree follows the same four-level structure as `data_sources.json`:
platform, then service, then log source, then the MITRE tactics and
techniques that source covers.

- **Click any row with an arrow** to expand or collapse it.
- **Click a technique** (the leaf level, no further arrow) to open a
  panel showing every other source in the catalog that also covers
  it, including sources you haven't expanded. Click an entry in that
  panel to jump straight to it in the tree.
- **Hover a log source or a technique** for a small panel with more
  detail: for a source, its coverage status and SIEM field mappings;
  for a technique, its MITRE ATT&CK ID, a direct link to its official
  page on attack.mitre.org, and the full list of tactics it belongs
  to.
- **Use the search box** to jump straight to a source or technique by
  name, without browsing down to it.
- **"Expand all platforms"** and **"Collapse all"** are in the
  sidebar, for a full overview or a clean reset.

Platforms and log sources are labeled with their technique count in
parentheses, and sorted richest-first at each level. This is
deliberate: it surfaces which sources are worth prioritizing directly
in the browsing experience, not as a separate report.

## Regenerating the tool

Regenerate `stc_map.html` any time you change
`data_sources.json` or `mitre_reference.json`:

```bash
python3 generate_stc_map.py -i data_sources.json -r mitre_reference.json -o stc_map.html --matrix all
```

The `--matrix` flag filters to a single domain instead of showing all
three:

```bash
python3 generate_stc_map.py -i data_sources.json -r mitre_reference.json -o datasource_map_enterprise.html --matrix enterprise
```

Valid values are `all`, `enterprise`, `mobile`, and `ics`.

## What the generator does, at a high level

`generate_stc_map.py` reads `data_sources.json` and
`mitre_reference.json`, builds a nested tree structure in Python, and
writes it as a single HTML file with the tree data embedded as JSON. A
technique that belongs to more than one of its own MITRE-defined
tactics appears under each one — this is accurate to the source data,
not a duplication bug. The generated file has no external JavaScript
dependency; all of the interaction logic is plain JavaScript embedded
in the file itself.

## Security

The generated file ships with a Content Security Policy restricting it
to loading resources only from itself and the two Google Fonts domains
it uses for typefaces. This applies whether the file is opened directly
(`file://`) or served over a network. It's a defense-in-depth measure
alongside the file's underlying JavaScript, which builds all
data-derived content (search results, hover details, cross-reference
entries) through direct DOM construction rather than HTML string
interpolation, and escapes any `</script>`-like sequence in the
embedded catalog data so it can't prematurely close the page's script
block.
