"""
Vector.dev log-parsing backend.

Shells out to the `vector` binary with a VRL transform that maps any
log format to the universal security schema. This is the same pipeline
that would run in production at scale (Redpanda → Vector → ClickHouse),
just invoked per-upload for the web UI.

Requires: `vector` binary on PATH.
  Install: curl --proto '=https' --tlsv1.2 -sSfL https://sh.vector.dev | bash

The VRL transform lives in vector.toml alongside this project.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from collections import Counter
from typing import Iterable

from .base import LogParser, ParseResult, ParsedRecord, ClusterInfo

VECTOR_BIN = os.environ.get("VECTOR_BIN", "vector")
VECTOR_CONFIG = os.environ.get("VECTOR_CONFIG", "vector.toml")

# schema fields in display order
SCHEMA_FIELDS = [
    ("timestamp",    "when"),
    ("log_level",    "severity"),
    ("event_type",   "type"),
    ("action",       "action"),
    ("status",       "status"),
    ("who_user",     "who:user"),
    ("who_userid",   "who:uid"),
    ("who_process",  "who:process"),
    ("src_ip",       "from:ip"),
    ("src_port",     "from:port"),
    ("src_machine",  "from:machine"),
    ("src_mac",      "from:mac"),
    ("from_user",    "from:user"),
    ("from_machine", "from:machine"),
    ("dst_ip",       "to:ip"),
    ("dst_port",     "to:port"),
    ("dst_machine",  "to:machine"),
    ("dst_mac",      "to:mac"),
    ("to_user",      "to:user"),
    ("to_machine",   "to:machine"),
    ("machine_id",   "machine_id"),
    ("protocol",     "proto"),
    ("resource",     "resource"),
]


def _check_vector() -> bool:
    """Check if the vector binary is available."""
    try:
        r = subprocess.run(
            [VECTOR_BIN, "--version"],
            capture_output=True, timeout=5,
        )
        return r.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _run_vector(lines: list[str], config: str) -> list[dict]:
    """
    Pipe log lines through vector and collect JSON output.

    We write logs to a temp file, run vector with stdin source,
    and capture structured JSON from stdout.
    """
    input_text = "\n".join(lines) + "\n"

    result = subprocess.run(
        [VECTOR_BIN, "--config", config, "--quiet"],
        input=input_text,
        capture_output=True,
        text=True,
        timeout=300,  # 5 min max
    )

    if result.returncode != 0:
        print(f"  vector stderr: {result.stderr[:500]}", file=sys.stderr)

    # parse JSON lines from stdout
    records = []
    for line in result.stdout.strip().splitlines():
        if not line.strip():
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    return records


def _schema_to_summary(event: dict) -> list[str]:
    """Convert a universal schema dict to the labeled parameter list for the UI."""
    out = []
    seen = set()
    for field, label in SCHEMA_FIELDS:
        val = event.get(field)
        if val is not None and str(val).strip():
            key = f"{label}={val}"
            if key not in seen:
                out.append(key)
                seen.add(key)
    return out


SAMPLE_RECORDS = 500


class VectorParser(LogParser):
    """
    Parse logs through Vector.dev's VRL transform.

    Uses the same vector.toml config that would run in production.
    Output maps to the universal security schema.
    """

    name = "vector"

    def __init__(self, config: str = VECTOR_CONFIG):
        self.config = config

    def parse(self, lines: Iterable[str],
              sample_limit: int = SAMPLE_RECORDS) -> ParseResult:

        # collect all lines (vector needs them all at once via stdin)
        all_lines = []
        for raw in lines:
            log = raw.rstrip("\n")
            if log.strip():
                all_lines.append(log)

        if not all_lines:
            return ParseResult(self.name, [], [])

        print(f"  vector: processing {len(all_lines)} lines...", file=sys.stderr)

        # run vector
        events = _run_vector(all_lines, self.config)

        if not events:
            raise RuntimeError(
                "Vector returned no output. Check vector.toml and that "
                "`vector --version` works."
            )

        print(f"  vector: got {len(events)} events", file=sys.stderr)

        # cluster by template (action + event_type + log_level combination)
        records: list[ParsedRecord] = []
        cluster_map: dict[str, int] = {}
        cluster_sizes: Counter = Counter()
        next_id = 1
        total_lines = 0
        total_params = 0
        new_clusters = 0

        for i, event in enumerate(events):
            raw = event.get("raw", all_lines[i] if i < len(all_lines) else "")

            # build template key from the structural fields
            tmpl_parts = []
            for f in ("event_type", "log_level", "action", "who_process"):
                v = event.get(f)
                if v is not None and str(v).strip():
                    tmpl_parts.append(f"{f}={v}")
            template = " | ".join(tmpl_parts) if tmpl_parts else "unknown"

            if template not in cluster_map:
                cluster_map[template] = next_id
                next_id += 1
                change = "new"
                new_clusters += 1
            else:
                change = "none"

            cid = cluster_map[template]
            cluster_sizes[cid] += 1

            summary = _schema_to_summary(event)
            total_lines += 1
            total_params += len(summary)

            if len(records) < sample_limit:
                records.append(ParsedRecord(
                    original_log=raw,
                    cluster_id=cid,
                    template=template,
                    parameters=summary,
                    change_type=change,
                ))

        clusters = []
        tmpl_by_id = {cid: tmpl for tmpl, cid in cluster_map.items()}
        for cid in sorted(tmpl_by_id):
            clusters.append(ClusterInfo(cid, cluster_sizes[cid], tmpl_by_id[cid]))
        clusters.sort(key=lambda c: c.size, reverse=True)

        result = ParseResult(self.name, records, clusters)
        result._total_lines = total_lines
        result._total_params = total_params
        result._new_clusters = new_clusters

        print(f"  vector: done — {total_lines} lines, {len(clusters)} clusters",
              file=sys.stderr)
        return result
