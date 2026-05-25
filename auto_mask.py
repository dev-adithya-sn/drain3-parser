#!/usr/bin/env python3
"""
auto_mask.py — learn masking rules from a log sample and write them to drain3.ini.

Why a calibration pass (not live .ini mutation)
-----------------------------------------------
drain3 builds its masker ONCE, when TemplateMiner is constructed, and masks
every line *before* it reaches the tree. Appending a rule mid-stream would
leave already-mined clusters holding un-masked tokens — an inconsistent tree.
The sound design is therefore:

    calibrate (sample)  ->  rewrite drain3.ini  ->  parse (frozen config)

This module does step 1. It does NOT invent regexes from scratch (that needs
an LLM and is unreliable). It matches sampled tokens against a curated CATALOG
of known-variable patterns and switches on the ones this log actually uses.
Re-running is idempotent — the .ini becomes a generated artifact whose single
source of truth is CATALOG below.

Two outputs:
  * AUTO-ADD  — catalog patterns that fire in the sample but aren't yet active
                are written into drain3.ini, sorted by priority (NUM last).
  * REVIEW    — token positions drain3 itself flagged as variable (<*>) that
                NO catalog entry recognises. These are printed for a human to
                inspect; nothing is auto-written, because a wrong synthesized
                regex would silently corrupt every template.

CLI
---
  python auto_mask.py calibrate <logfile> [--config drain3.ini] [--sample N]
  python auto_mask.py calibrate <logfile> --dry-run     # show, don't write
"""
import argparse
import json
import re
import sys
import tempfile
from collections import defaultdict
from pathlib import Path

from parse_logs import _build_miner, extract_parameters, masked_content

# ── Pattern catalog ───────────────────────────────────────────────────────────
# (priority, mask_name, regex)  — lower priority is applied EARLIER, so more
# specific composites sit above broad catch-alls; NUM is always last.
# To teach the tool a new format, add ONE line here.
CATALOG = [
    (10, "TIMESTAMP", r"\b\d{4}-\d{2}-\d{2}[T_ ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b"),
    (11, "TIMESTAMP", r"\b\d{4}-\d{2}-\d{2}-\d{2}\.\d{2}\.\d{2}\.\d+\b"),
    (12, "TIMESTAMP", r"(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) [ \d]\d \d{2}:\d{2}:\d{2}(?:\.\d+)?"),
    (13, "TIMESTAMP", r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) +\d{1,2} \d{2}:\d{2}:\d{2}(?:[.,]\d+)?"),
    (14, "TIMESTAMP", r"\b\d{2}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}\b"),
    (15, "TIMESTAMP", r"\b\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?\b"),
    (16, "TIMESTAMP", r"\b\d{6} \d{6}\b"),
    (20, "DATE",      r"\b\d{4}\.\d{2}\.\d{2}\b"),
    (30, "UUID",      r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"),
    (35, "MAC",       r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b"),
    (40, "IP",        r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::\d{1,5})?\b"),
    (45, "EMAIL",     r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"),
    (50, "URL",       r"\b(?:https?|ftp)://\S+"),
    (55, "HEX",       r"\b0[xX][0-9a-fA-F]+\b"),
    (60, "TIME",      r"\b\d{1,2}:\d{2}:\d{2}(?:[.,]\d+)?\b"),
    (90, "NUM",       r"(?<![\w./-])\d{2,}(?![\w./-])"),
]
_COMPILED = [(p, n, pat, re.compile(pat)) for p, n, pat in CATALOG]


# ── .ini read / write ─────────────────────────────────────────────────────────

def read_ini(path: str):
    """Return (full_text, list_of_active_rule_dicts)."""
    text = Path(path).read_text(encoding="utf-8")
    m = re.search(r"masking\s*=\s*(\[.*?\n\s*\])", text, re.DOTALL)
    if not m:
        return text, []
    try:
        return text, json.loads(m.group(1))
    except json.JSONDecodeError:
        return text, []


def render_masking(active: list) -> str:
    """active: list of (priority, name, pattern). Render the masking block."""
    active = sorted(set(active))
    rows = [
        '    {"regex_pattern": %s, "mask_with": %s}'
        % (json.dumps(pat), json.dumps(name))
        for _, name, pat in active
    ]
    return "masking = [\n" + ",\n".join(rows) + "\n    ]"


def write_ini(path: str, text: str, active: list) -> None:
    block = render_masking(active)
    # NB: pass a function as the replacement — a plain string would let re.sub
    # interpret backslashes (\\b -> \b), corrupting the JSON-escaped regexes.
    if re.search(r"masking\s*=\s*\[.*?\n\s*\]", text, re.DOTALL):
        text = re.sub(r"masking\s*=\s*\[.*?\n\s*\]",
                      lambda _m: block, text, flags=re.DOTALL)
    elif "[MASKING]" in text:
        text = text.replace("[MASKING]", "[MASKING]\n" + block, 1)
    else:
        text = text.rstrip() + "\n\n[MASKING]\n" + block + "\n"
    Path(path).write_text(text, encoding="utf-8")


# ── Sampling ──────────────────────────────────────────────────────────────────

def sample_lines(path: str, n: int) -> list:
    out = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if line.strip():
                out.append(line)
            if len(out) >= n:
                break
    return out


# ── Detection ─────────────────────────────────────────────────────────────────

def detect_catalog(lines: list, active_patterns: set) -> list:
    """Catalog entries that fire often enough but aren't active yet."""
    floor = max(5, len(lines) // 200)          # >=0.5% of sample, min 5 lines
    found = []
    for prio, name, pat, rx in _COMPILED:
        if pat in active_patterns:
            continue
        hits = sum(1 for ln in lines if rx.search(ln))
        if hits >= floor:
            found.append((prio, name, pat, hits))
    return found


def detect_novel(log_path: str, config: str, lines: list) -> list:
    """
    Run drain3 once with the current config, inspect the values it dropped
    into <*> positions. Report positions that are highly variable but match
    NO catalog entry — candidates for a human-written rule.
    """
    with tempfile.TemporaryDirectory() as tmp:
        # a path inside tmp that does NOT exist yet — drain3 starts a fresh tree
        miner = _build_miner(str(Path(tmp) / "calib.bin"), config)
        vals = defaultdict(list)
        for ln in lines:
            res    = miner.add_log_message(ln)
            tmpl   = res["template_mined"].split()
            masked = masked_content(miner, ln).split()
            if len(tmpl) != len(masked):
                continue
            for i, (t, v) in enumerate(zip(tmpl, masked)):
                if t == "<*>":
                    vals[(res["cluster_id"], i)].append(v)

    novel = []
    for key, vs in vals.items():
        if len(vs) < 20:                       # too rare to judge
            continue
        distinct = set(vs)
        if len(distinct) < 0.5 * len(vs):      # low cardinality => likely enum
            continue
        probe   = list(distinct)[:25]
        recognised = sum(
            1 for v in probe if any(rx.search(v) for _, _, _, rx in _COMPILED)
        )
        if recognised < 0.5 * len(probe):      # catalog doesn't know this
            novel.append((len(distinct), len(vs), list(distinct)[:3]))

    # collapse entries that share a token "shape" (digits->#, letters->@)
    def shape(s: str) -> str:
        return re.sub(r"[A-Za-z]", "@", re.sub(r"\d", "#", s))

    best: dict = {}
    for distinct, total, examples in novel:
        sig = shape(examples[0]) if examples else ""
        if sig not in best or distinct > best[sig][0]:
            best[sig] = (distinct, total, examples)
    novel = sorted(best.values(), reverse=True)
    return novel


# ── Calibrate ─────────────────────────────────────────────────────────────────

def calibrate(log_path: str, config: str, sample_n: int, dry_run: bool) -> None:
    text, active_rules = read_ini(config)
    active_patterns = {r["regex_pattern"] for r in active_rules}

    # custom rules not in catalog: keep them, warn
    catalog_patterns = {pat for _, _, pat in CATALOG}
    custom = [r for r in active_rules if r["regex_pattern"] not in catalog_patterns]
    for r in custom:
        print(f"  ! custom rule kept (not in CATALOG): {r['mask_with']}", file=sys.stderr)

    lines = sample_lines(log_path, sample_n)
    print(f"  sampled {len(lines)} lines from {log_path}", file=sys.stderr)

    new = detect_catalog(lines, active_patterns)
    novel = detect_novel(log_path, config, lines)

    if new:
        print("  AUTO-ADD (catalog patterns this log uses):", file=sys.stderr)
        for prio, name, pat, hits in sorted(new):
            print(f"    + <{name}>  ({hits}/{len(lines)} lines)  {pat}", file=sys.stderr)
    else:
        print("  AUTO-ADD: nothing new — config already covers this log.", file=sys.stderr)

    if novel:
        print("  REVIEW (variable tokens no catalog entry matches — add to CATALOG if a real format):", file=sys.stderr)
        for distinct, total, examples in novel[:6]:
            ex = ", ".join(examples)
            print(f"    ? {distinct} distinct / {total} seen  e.g. {ex}", file=sys.stderr)

    if dry_run:
        print("  --dry-run: drain3.ini not modified.", file=sys.stderr)
        return

    # merge: existing catalog rules + custom + newly detected, priority-sorted
    final = {(p, n, pat) for p, n, pat in CATALOG
             if pat in active_patterns or any(pat == x[2] for x in new)}
    for i, r in enumerate(custom):             # custom rules sit just before NUM
        final.add((89, r["mask_with"], r["regex_pattern"]))
    write_ini(config, text, list(final))
    print(f"  drain3.ini updated — {len(final)} masking rules active.", file=sys.stderr)


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    pc = sub.add_parser("calibrate", help="Learn masks from a log and update drain3.ini")
    pc.add_argument("logfile")
    pc.add_argument("--config",  default="drain3.ini")
    pc.add_argument("--sample",  type=int, default=5000)
    pc.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    if a.cmd == "calibrate":
        calibrate(a.logfile, a.config, a.sample, a.dry_run)


if __name__ == "__main__":
    main()
