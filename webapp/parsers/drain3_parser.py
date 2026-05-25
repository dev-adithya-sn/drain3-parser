"""
drain3 log-parsing backend.

Wraps drain3's TemplateMiner behind the LogParser interface. Uses an
in-memory miner (no persistence handler) so every uploaded file is parsed
against a fresh tree — predictable and stateless, which is what a web
upload wants. The masking config is still loaded from drain3.ini.
"""
from __future__ import annotations

import os
from typing import Iterable

from drain3 import TemplateMiner
from drain3.template_miner_config import TemplateMinerConfig

from .base import ClusterInfo, LogParser, ParsedRecord, ParseResult

# drain3.ini is resolved relative to the process working directory.
# Run the server from the pure_drain folder (where drain3.ini lives).
CONFIG_FILE = os.environ.get("DRAIN3_CONFIG", "drain3.ini")


def _extract_parameters(template: str, masked_log: str) -> list[str]:
    """Token-zip the masked log against the template; collect <*> values."""
    tmpl = template.split()
    toks = masked_log.split()
    if len(tmpl) != len(toks):
        return []
    return [tok for tt, tok in zip(tmpl, toks) if tt == "<*>"]


class Drain3Parser(LogParser):
    """Cluster logs and extract parameters with drain3."""

    name = "drain3"

    def __init__(self, config_file: str = CONFIG_FILE) -> None:
        cfg = TemplateMinerConfig()
        cfg.load(config_file)
        # no persistence_handler -> fresh in-memory tree per instance
        self._miner = TemplateMiner(config=cfg)

    def _mask(self, log: str) -> str:
        """Apply drain3's own masking, exposed so parameters line up."""
        masker = getattr(self._miner, "masker", None)
        return masker.mask(log) if masker is not None else log

    def parse(self, lines: Iterable[str]) -> ParseResult:
        records: list[ParsedRecord] = []

        for raw in lines:
            log = raw.rstrip("\n")
            if not log.strip():
                continue

            res      = self._miner.add_log_message(log)
            template = res["template_mined"]

            records.append(ParsedRecord(
                original_log = log,
                cluster_id   = res["cluster_id"],
                template     = template,
                parameters   = _extract_parameters(template, self._mask(log)),
                change_type  = res["change_type"],
            ))

        clusters = [
            ClusterInfo(c.cluster_id, c.size, c.get_template())
            for c in self._miner.drain.id_to_cluster.values()
        ]
        clusters.sort(key=lambda c: c.size, reverse=True)

        return ParseResult(self.name, records, clusters)
