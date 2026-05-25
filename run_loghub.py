#!/usr/bin/env python3
"""
Batch-run the drain3 parser over every loghub dataset.

Usage:
  python run_loghub.py [LOGHUB_DIR]              parse with the current drain3.ini
  python run_loghub.py [LOGHUB_DIR] --calibrate  auto-learn masks per dataset first

Each dataset gets an ISOLATED drain3 tree — mixing 16 unrelated log formats
into one tree is meaningless and risks cluster eviction, so every *_2k.log
gets its own state file and its own JSONL output.

With --calibrate, auto_mask.calibrate() runs on each dataset before it is
parsed: it samples the file, detects which catalog patterns the log uses,
and writes them into drain3.ini. The config is frozen for that dataset's
parse, then extended again for the next — so the .ini grows as new formats
appear, which is the safe form of "dynamically updating the .ini".

Outputs:
  loghub_out/<Dataset>.jsonl     parsed records
  loghub_state/<Dataset>.bin     persisted drain3 tree
"""
import argparse
import contextlib
import io
import sys
import time
from pathlib import Path

from parse_logs import process_logs, _build_miner

CONFIG    = "drain3.ini"
OUT_DIR   = Path("loghub_out")
STATE_DIR = Path("loghub_state")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("loghub_dir", nargs="?", default="loghub")
    ap.add_argument("--calibrate", action="store_true",
                    help="auto-learn masking rules from each dataset before parsing")
    args = ap.parse_args()

    root = Path(args.loghub_dir)
    if not root.is_dir():
        sys.exit(f"loghub dir not found: {root}  (clone logpai/loghub first)")

    logs = sorted(root.glob("*/*_2k.log"))
    if not logs:
        sys.exit(f"no *_2k.log files under {root}")

    if args.calibrate:
        from auto_mask import calibrate           # imported lazily

    OUT_DIR.mkdir(exist_ok=True)
    STATE_DIR.mkdir(exist_ok=True)

    print(f"{'Dataset':<14}{'Lines':>8}{'Clusters':>10}{'Time':>8}")
    print("-" * 40)
    tot_lines = tot_clusters = 0

    for log in logs:
        name  = log.parent.name
        out   = OUT_DIR / f"{name}.jsonl"
        state = STATE_DIR / f"{name}.bin"
        state.unlink(missing_ok=True)            # fresh, isolated tree

        t0 = time.time()
        with contextlib.redirect_stderr(io.StringIO()):     # mute progress noise
            if args.calibrate:
                calibrate(str(log), CONFIG, sample_n=5000, dry_run=False)
            n = process_logs(str(log), str(out), str(state), CONFIG)
        ncl = len(_build_miner(str(state), CONFIG).drain.id_to_cluster)

        tot_lines    += n
        tot_clusters += ncl
        print(f"{name:<14}{n:>8,}{ncl:>10}{time.time()-t0:>7.1f}s")

    print("-" * 40)
    print(f"{'TOTAL':<14}{tot_lines:>8,}{tot_clusters:>10}")
    print(f"\n{len(logs)} datasets parsed -> {OUT_DIR}/  (state -> {STATE_DIR}/)")
    if args.calibrate:
        print(f"masking rules learned into {CONFIG}")


if __name__ == "__main__":
    main()