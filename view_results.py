#!/usr/bin/env python3
"""
Generate an HTML quality report comparing raw logs vs drain3-parsed output.

Usage:
  python view_results.py loghub_out/Spark.jsonl          # one dataset
  python view_results.py loghub_out/*.jsonl               # all datasets
  python view_results.py loghub_out/HDFS.jsonl -o report  # custom output name

Opens the report in your default browser automatically.
"""
import argparse
import html
import json
import re
import sys
import webbrowser
from collections import Counter, defaultdict
from pathlib import Path


def load_records(path: str) -> list[dict]:
    records = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def highlight_diff(raw: str, template: str) -> str:
    """
    Produce an HTML version of the raw log where tokens that got
    masked or wildcarded are wrapped in <mark> tags.
    """
    raw_toks = raw.split()
    tmpl_toks = template.split()

    # token counts can differ (masking can merge tokens, e.g. "2024-01-15 10:23:45" -> "<TIMESTAMP>")
    # fall back to simple display if alignment is impossible
    if len(raw_toks) == len(tmpl_toks):
        parts = []
        for rt, tt in zip(raw_toks, tmpl_toks):
            esc = html.escape(rt)
            if tt != rt:
                parts.append(f'<mark>{esc}</mark>')
            else:
                parts.append(esc)
        return " ".join(parts)

    # alignment mismatch: highlight tokens in raw that appear as masks in template
    mask_re = re.compile(r"<[A-Z_]+>|<\*>")
    masks_in_template = set(mask_re.findall(template))
    if not masks_in_template:
        return html.escape(raw)

    # highlight anything in raw that's "replaced" — approximate by coloring
    # tokens not found verbatim in the template
    tmpl_set = set(tmpl_toks)
    parts = []
    for rt in raw_toks:
        esc = html.escape(rt)
        if rt not in tmpl_set:
            parts.append(f'<mark>{esc}</mark>')
        else:
            parts.append(esc)
    return " ".join(parts)


def build_html(all_data: dict[str, list[dict]]) -> str:
    """all_data: {dataset_name: [records]}"""
    dataset_sections = []

    for name, records in sorted(all_data.items()):
        n = len(records)
        clusters = defaultdict(list)
        for r in records:
            clusters[r["cluster_id"]].append(r)
        n_clusters = len(clusters)
        change_counts = Counter(r["change_type"] for r in records)
        param_total = sum(len(r["parameters"]) for r in records)

        # cluster frequency table
        cluster_rows = []
        for cid, recs in sorted(clusters.items(), key=lambda x: -len(x[1])):
            tmpl = recs[-1]["template"]  # latest template
            cluster_rows.append(f"""
                <tr>
                    <td class="num">{cid}</td>
                    <td class="num">{len(recs):,}</td>
                    <td class="tpl">{html.escape(tmpl)}</td>
                </tr>""")

        # sample comparison rows (first 80 records)
        sample_rows = []
        for r in records[:80]:
            hl = highlight_diff(r["original_log"], r["template"])
            params = ", ".join(r["parameters"]) if r["parameters"] else "—"
            badge = ""
            if r["change_type"] == "new":
                badge = '<span class="badge new">NEW</span>'
            elif r["change_type"] == "cluster_template_changed":
                badge = '<span class="badge changed">CHANGED</span>'
            sample_rows.append(f"""
                <tr>
                    <td class="num">{r['cluster_id']}</td>
                    <td class="raw">{hl}</td>
                    <td class="tpl">{html.escape(r['template'])}</td>
                    <td class="params">{html.escape(params)}</td>
                    <td>{badge}</td>
                </tr>""")

        dataset_sections.append(f"""
        <section class="dataset" id="ds-{html.escape(name)}">
            <h2>{html.escape(name)}</h2>
            <div class="stats">
                <div class="stat"><span class="val">{n:,}</span><span class="label">lines</span></div>
                <div class="stat"><span class="val">{n_clusters}</span><span class="label">clusters</span></div>
                <div class="stat"><span class="val">{param_total:,}</span><span class="label">params extracted</span></div>
                <div class="stat"><span class="val">{change_counts.get('new',0)}</span><span class="label">new clusters</span></div>
            </div>

            <h3>Cluster Map</h3>
            <table class="cluster-table">
                <thead><tr><th>ID</th><th>Logs</th><th>Template</th></tr></thead>
                <tbody>{"".join(cluster_rows)}</tbody>
            </table>

            <h3>Raw vs Parsed <span class="subtitle">(first {min(80, n)} lines — highlighted tokens were masked or wildcarded)</span></h3>
            <table class="compare-table">
                <thead><tr><th>CID</th><th>Raw Log (highlights = changed)</th><th>Template</th><th>Parameters</th><th></th></tr></thead>
                <tbody>{"".join(sample_rows)}</tbody>
            </table>
        </section>""")

    # navigation tabs
    nav_items = "".join(
        f'<a href="#ds-{html.escape(n)}" class="nav-tab">{html.escape(n)}</a>'
        for n in sorted(all_data)
    )
    total_lines = sum(len(r) for r in all_data.values())
    total_clusters = sum(
        len(set(r["cluster_id"] for r in recs)) for recs in all_data.values()
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>drain3 parsing report</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=DM+Sans:wght@400;500;700&display=swap');

  :root {{
    --bg: #0e1117;
    --surface: #161b22;
    --border: #30363d;
    --text: #c9d1d9;
    --text-dim: #8b949e;
    --accent: #58a6ff;
    --green: #3fb950;
    --orange: #d29922;
    --red: #f85149;
    --mark-bg: #341a00;
    --mark-border: #6e4008;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: 'DM Sans', system-ui, sans-serif;
    background: var(--bg); color: var(--text);
    line-height: 1.5; padding: 2rem; max-width: 100%;
  }}
  h1 {{
    font-size: 1.6rem; font-weight: 700; margin-bottom: .3rem;
    color: #fff; letter-spacing: -0.02em;
  }}
  .header-sub {{ color: var(--text-dim); font-size: .9rem; margin-bottom: 1.2rem; }}
  .nav {{ display: flex; flex-wrap: wrap; gap: .4rem; margin-bottom: 2rem; }}
  .nav-tab {{
    padding: .35rem .8rem; border-radius: 6px; font-size: .8rem;
    background: var(--surface); color: var(--accent); text-decoration: none;
    border: 1px solid var(--border); transition: background .15s;
  }}
  .nav-tab:hover {{ background: #1c2333; }}
  .dataset {{ margin-bottom: 3rem; }}
  h2 {{
    font-size: 1.3rem; color: #fff; margin-bottom: .8rem;
    padding-bottom: .4rem; border-bottom: 2px solid var(--accent);
    display: inline-block;
  }}
  h3 {{ font-size: 1rem; color: var(--text-dim); margin: 1.2rem 0 .6rem; }}
  .subtitle {{ font-weight: 400; font-size: .8rem; }}
  .stats {{
    display: flex; gap: 1.5rem; margin-bottom: 1.2rem; flex-wrap: wrap;
  }}
  .stat {{
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 8px; padding: .6rem 1rem; min-width: 100px;
  }}
  .stat .val {{ display: block; font-size: 1.4rem; font-weight: 700; color: #fff; }}
  .stat .label {{ font-size: .75rem; color: var(--text-dim); text-transform: uppercase; letter-spacing: .04em; }}

  table {{
    width: 100%; border-collapse: collapse; font-size: .78rem;
    font-family: 'JetBrains Mono', monospace;
  }}
  thead th {{
    text-align: left; padding: .5rem .6rem; color: var(--text-dim);
    border-bottom: 2px solid var(--border); font-weight: 600;
    font-family: 'DM Sans', sans-serif; font-size: .75rem;
    text-transform: uppercase; letter-spacing: .04em;
    position: sticky; top: 0; background: var(--bg); z-index: 1;
  }}
  td {{
    padding: .35rem .6rem; border-bottom: 1px solid var(--border);
    vertical-align: top; max-width: 600px; overflow-wrap: break-word;
  }}
  tr:hover td {{ background: #1c2333; }}
  .num {{ text-align: right; color: var(--accent); white-space: nowrap; }}
  .tpl {{ color: var(--green); }}
  .raw {{ color: var(--text); }}
  .params {{ color: var(--orange); }}

  mark {{
    background: var(--mark-bg); color: #ffb347;
    border: 1px solid var(--mark-border); border-radius: 3px;
    padding: 0 2px; font-weight: 600;
  }}
  .badge {{
    display: inline-block; padding: .1rem .4rem; border-radius: 4px;
    font-size: .65rem; font-weight: 600; font-family: 'DM Sans', sans-serif;
    text-transform: uppercase; letter-spacing: .03em;
  }}
  .badge.new {{ background: #0d2818; color: var(--green); border: 1px solid #1a4028; }}
  .badge.changed {{ background: #2a1a00; color: var(--orange); border: 1px solid #4a3000; }}

  .cluster-table {{ margin-bottom: 1rem; }}
  .compare-table td {{ font-size: .72rem; }}
</style>
</head>
<body>
<h1>drain3 Parsing Report</h1>
<p class="header-sub">{len(all_data)} dataset(s) &middot; {total_lines:,} lines &middot; {total_clusters} clusters</p>
<nav class="nav">{nav_items}</nav>
{"".join(dataset_sections)}
</body>
</html>"""


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("jsonl", nargs="+", help="One or more parsed JSONL files")
    ap.add_argument("-o", "--output", default="drain3_report",
                    help="Output filename (without .html)")
    ap.add_argument("--no-open", action="store_true",
                    help="Don't auto-open in browser")
    args = ap.parse_args()

    all_data = {}
    for path in args.jsonl:
        name = Path(path).stem
        records = load_records(path)
        if records:
            all_data[name] = records
            print(f"  loaded {name}: {len(records):,} records", file=sys.stderr)

    if not all_data:
        sys.exit("no records loaded")

    out = Path(f"{args.output}.html")
    out.write_text(build_html(all_data), encoding="utf-8")
    print(f"\n  report -> {out}", file=sys.stderr)

    if not args.no_open:
        webbrowser.open(str(out.resolve()))


if __name__ == "__main__":
    main()
