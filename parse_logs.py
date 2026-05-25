#!/usr/bin/env python3
"""
Drain3 log parser — clusters logs, extracts parameters, persists state.

Usage
-----
  python parse_logs.py                         # run on raw_logs.txt
  python parse_logs.py run [IN] [OUT]          # explicit paths
  python parse_logs.py test                    # smoke-test with built-in samples
  python parse_logs.py clusters                # list all saved clusters
  python parse_logs.py edit <ID> "<template>"  # rewrite a cluster template
  python parse_logs.py show <ID>               # inspect one cluster

Each processed line is written to parsed_logs.jsonl as:
  {
    "original_log" : "<raw line>",
    "cluster_id"   : 7,
    "template"     : "User <*> logged in from <IP>",
    "parameters"   : ["alice"],           # values at <*> positions
    "change_type"  : "none"               # "new" | "cluster_template_changed" | "none"
  }

Notes on masking vs parameters
-------------------------------
Masks (<TIMESTAMP>, <IP>, <HEX>, <NUM>) are applied *before* the log reaches
the drain3 tree, so those tokens appear as constants inside templates.
Drain3's own <*> wildcard marks positions that vary *between* logs (e.g. a
username, a filename, a session-id).  The "parameters" list captures those
drain3-discovered variable values; the original log always preserves the
unmasked text for full auditing.
"""

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

from drain3 import TemplateMiner
from drain3.file_persistence import FilePersistence
from drain3.template_miner_config import TemplateMinerConfig

CONFIG_FILE  = "drain3.ini"
STATE_FILE   = "drain3_state.bin"
INPUT_FILE   = "raw_logs.txt"
OUTPUT_FILE  = "parsed_logs.jsonl"
WRITE_BUFFER = 500   # lines to accumulate before flushing output


# ── Parameter extraction ──────────────────────────────────────────────────────

def extract_parameters(template: str, masked_log: str) -> list[str]:
    """
    Token-level match of *masked_log* against *template*.
    Returns the actual token values wherever the template has <*>.

    Drain3 is token-based (whitespace-delimited), so <*> always maps to
    exactly one token — no regex needed, O(n) over token count.
    """
    tmpl_toks = template.split()
    log_toks  = masked_log.split()
    if len(tmpl_toks) != len(log_toks):
        return []
    return [lt for tt, lt in zip(tmpl_toks, log_toks) if tt == "<*>"]


def masked_content(miner: TemplateMiner, log_line: str) -> str:
    """Apply the same masking drain3 uses internally, exposed for reuse."""
    if hasattr(miner, "masker") and miner.masker is not None:
        return miner.masker.mask(log_line)
    return log_line


# ── Core processing ───────────────────────────────────────────────────────────

def _build_miner(state_file: str = STATE_FILE,
                 config_file: str = CONFIG_FILE) -> TemplateMiner:
    cfg = TemplateMinerConfig()
    cfg.load(config_file)
    return TemplateMiner(
        persistence_handler=FilePersistence(state_file),
        config=cfg,
    )


def process_logs(
    input_path:  str = INPUT_FILE,
    output_path: str = OUTPUT_FILE,
    state_file:  str = STATE_FILE,
    config_file: str = CONFIG_FILE,
) -> int:
    """
    Parse every line of *input_path*, write JSONL to *output_path*, save state.
    Returns the number of lines processed.
    """
    miner = _build_miner(state_file, config_file)

    processed = 0
    buf: list[str] = []

    with open(input_path, encoding="utf-8") as fin, \
         open(output_path, "w", encoding="utf-8") as fout:

        for raw in fin:
            log_line = raw.rstrip("\n")
            if not log_line.strip():
                continue

            result   = miner.add_log_message(log_line)
            template = result["template_mined"]
            params   = extract_parameters(template, masked_content(miner, log_line))

            record = {
                "original_log": log_line,
                "cluster_id":   result["cluster_id"],
                "template":     template,
                "parameters":   params,
                "change_type":  result["change_type"],
            }
            
            buf.append(json.dumps(record, ensure_ascii=False))
            processed += 1

            if len(buf) >= WRITE_BUFFER:
                fout.write("\n".join(buf) + "\n")
                buf.clear()
                print(f"\r  {processed:,} lines processed…", end="", file=sys.stderr)

        if buf:
            fout.write("\n".join(buf) + "\n")

    miner.save_state("final")

    n_clusters = len(miner.drain.id_to_cluster)
    print(
        f"\r  Done. {processed:,} lines → {output_path}  "
        f"({n_clusters} clusters, state → {state_file})",
        file=sys.stderr,
    )
    return processed


# ── Cluster inspection and editing ───────────────────────────────────────────

def list_clusters(state_file: str = STATE_FILE,
                  config_file: str = CONFIG_FILE) -> None:
    """Print every cluster in the saved tree (id, log-count, template)."""
    miner    = _build_miner(state_file, config_file)
    clusters = miner.drain.id_to_cluster
    if not clusters:
        print("No clusters saved yet — run the parser first.")
        return
    width = max(len(c.get_template()) for c in clusters.values())
    print(f"{'ID':>6}  {'Logs':>8}  Template")
    print("-" * min(width + 20, 120))
    for cid, cluster in sorted(clusters.items()):
        print(f"{cid:>6}  {cluster.size:>8}  {cluster.get_template()}")


def show_cluster(cluster_id: int,
                 state_file: str  = STATE_FILE,
                 config_file: str = CONFIG_FILE) -> None:
    """Print detailed info for one cluster."""
    miner   = _build_miner(state_file, config_file)
    cluster = miner.drain.id_to_cluster.get(cluster_id)
    if cluster is None:
        print(f"No cluster with id={cluster_id}.", file=sys.stderr)
        sys.exit(1)
    print(json.dumps({
        "cluster_id": cluster.cluster_id,
        "log_count":  cluster.size,
        "template":   cluster.get_template(),
        "tokens":     cluster.log_template_tokens,
    }, indent=2, ensure_ascii=False))


def rename_cluster(cluster_id: int,
                   new_template: str,
                   state_file:  str = STATE_FILE,
                   config_file: str = CONFIG_FILE) -> None:
    """
    Overwrite a cluster's template tokens and persist the change.

    Use <*> in *new_template* to mark variable positions.
    Example:  rename_cluster(7, "User <*> signed in from <IP>")

    Editing tips
    ------------
    • list_clusters()  shows ids and current templates.
    • Tokens are whitespace-split, so "<*>" must be a standalone word.
    • After renaming, new logs still route to this cluster if their
      similarity to the new template meets sim_th from drain3.ini.
    • To merge two clusters, rename one to match the other's template,
      then re-run the parser — drain3 will absorb them over time.
    • There is no undo; make a backup copy of the .bin file first.
    """
    miner   = _build_miner(state_file, config_file)
    cluster = miner.drain.id_to_cluster.get(cluster_id)
    if cluster is None:
        print(f"No cluster with id={cluster_id}.", file=sys.stderr)
        sys.exit(1)
    old = cluster.get_template()
    cluster.log_template_tokens = new_template.split()
    miner.save_state("manual_edit")
    print(f"Cluster {cluster_id} updated.")
    print(f"  Before: {old}")
    print(f"  After:  {cluster.get_template()}")


# ── Smoke test ────────────────────────────────────────────────────────────────

# Representative samples: timestamps, IPs, hex, numbers, usernames — all in one
# set so you can verify that masking + clustering + parameter extraction work.
SAMPLE_LOGS = [
    "2024-01-15 10:23:45 INFO  User alice logged in from 192.168.1.10",
    "2024-01-15 10:24:01 INFO  User bob logged in from 10.0.0.5",
    "2024-01-15T10:25:10Z INFO  User carol logged in from 172.16.0.3",
    "2024-01-15 10:25:30 ERROR Connection to 172.16.0.1 failed after 3 retries",
    "2024-01-15 10:25:31 ERROR Connection to 172.16.0.2 failed after 5 retries",
    "2024-01-15 10:26:00 DEBUG Allocated 0x1a2b3c bytes in block 42",
    "2024-01-15 10:26:05 DEBUG Allocated 0xdeadbeef bytes in block 99",
    "2024-01-15 10:26:10 WARN  Disk usage at 87 percent on /var/log",
    "2024-01-15 10:26:15 WARN  Disk usage at 91 percent on /home",
    "2024-01-15 10:27:00 INFO  Service started on port 8080",
    "2024-01-15 10:27:05 INFO  Service started on port 9090",
    "2024-01-15 10:27:10 INFO  User dave logged in from 192.168.2.20",
]


def run_smoke_test(config_file: str = CONFIG_FILE) -> None:
    """
    Feed SAMPLE_LOGS through the parser in a temp directory and pretty-print
    the JSONL output.  Does not touch the production state file.

    How to test drain3 effectively
    --------------------------------
    1. Start with 8–20 representative log lines covering your major patterns.
    2. Run  `python parse_logs.py test`  and check that:
         - Semantically identical lines share a cluster_id.
         - Templates show <TIMESTAMP>/<IP>/<HEX>/<NUM> where expected.
         - True variable fields (usernames, paths) appear as <*> in templates
           and as non-empty entries in "parameters".
    3. Tune drain3.ini:
         - Lower sim_th  → more templates merged (may over-generalise).
         - Higher sim_th → clusters stay distinct (may under-merge).
         - Add/remove masking rules to control what becomes a constant vs <*>.
    4. Once happy, run on your full log file and inspect parsed_logs.jsonl.
    5. Use `python parse_logs.py clusters` to audit the final cluster map.
    """
    with tempfile.TemporaryDirectory() as tmp:
        in_file    = os.path.join(tmp, "test_logs.txt")
        out_file   = os.path.join(tmp, "test_out.jsonl")
        state_file = os.path.join(tmp, "test_state.bin")

        Path(in_file).write_text("\n".join(SAMPLE_LOGS), encoding="utf-8")
        process_logs(in_file, out_file, state_file=state_file, config_file=config_file)

        print("\n── Smoke-test results ────────────────────────────────────────")
        with open(out_file, encoding="utf-8") as f:
            for line in f:
                record = json.loads(line)
                # Pretty-print only the interesting fields
                print(json.dumps({
                    k: record[k]
                    for k in ("cluster_id", "template", "parameters", "original_log")
                }, ensure_ascii=False))
        print("─────────────────────────────────────────────────────────────")


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    ap = argparse.ArgumentParser(
        description="Drain3 log parser — cluster, extract, persist.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = ap.add_subparsers(dest="cmd")

    # run
    p_run = sub.add_parser("run", help="Parse logs (default command)")
    p_run.add_argument("input",  nargs="?", default=INPUT_FILE)
    p_run.add_argument("output", nargs="?", default=OUTPUT_FILE)
    p_run.add_argument("--state",  default=STATE_FILE)
    p_run.add_argument("--config", default=CONFIG_FILE)

    # test
    p_test = sub.add_parser("test", help="Smoke-test with built-in sample logs")
    p_test.add_argument("--config", default=CONFIG_FILE)

    # clusters
    p_cl = sub.add_parser("clusters", help="List all saved clusters")
    p_cl.add_argument("--state",  default=STATE_FILE)
    p_cl.add_argument("--config", default=CONFIG_FILE)

    # show
    p_sh = sub.add_parser("show", help="Inspect a single cluster")
    p_sh.add_argument("id", type=int)
    p_sh.add_argument("--state",  default=STATE_FILE)
    p_sh.add_argument("--config", default=CONFIG_FILE)

    # edit
    p_ed = sub.add_parser("edit", help="Rewrite a cluster's template")
    p_ed.add_argument("id", type=int, help="Cluster ID (from 'clusters')")
    p_ed.add_argument("template",
                      help='New template, e.g. "User <*> logged in from <IP>"')
    p_ed.add_argument("--state",  default=STATE_FILE)
    p_ed.add_argument("--config", default=CONFIG_FILE)

    args = ap.parse_args()

    if args.cmd == "test":
        run_smoke_test(config_file=args.config)
    elif args.cmd == "clusters":
        list_clusters(state_file=args.state, config_file=args.config)
    elif args.cmd == "show":
        show_cluster(args.id, state_file=args.state, config_file=args.config)
    elif args.cmd == "edit":
        rename_cluster(args.id, args.template,
                       state_file=args.state, config_file=args.config)
    else:
        # "run" or bare invocation
        in_  = getattr(args, "input",  INPUT_FILE)
        out_ = getattr(args, "output", OUTPUT_FILE)
        st   = getattr(args, "state",  STATE_FILE)
        cfg  = getattr(args, "config", CONFIG_FILE)
        process_logs(in_, out_, state_file=st, config_file=cfg)


if __name__ == "__main__":
    main()
