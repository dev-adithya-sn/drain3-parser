from __future__ import annotations
import os
from typing import Iterable
from drain3 import TemplateMiner
from drain3.template_miner_config import TemplateMinerConfig
from .base import ClusterInfo, LogParser, ParsedRecord, ParseResult

CONFIG_FILE = os.environ.get("DRAIN3_CONFIG", "drain3.ini")
SAMPLE_RECORDS = 500

def _extract_parameters(template, masked_log):
    tmpl, toks = template.split(), masked_log.split()
    return [tok for tt, tok in zip(tmpl, toks) if tt == "<*>"] if len(tmpl) == len(toks) else []

class Drain3Parser(LogParser):
    name = "drain3"
    def __init__(self, config_file=CONFIG_FILE):
        cfg = TemplateMinerConfig(); cfg.load(config_file)
        self._miner = TemplateMiner(config=cfg)
    def _mask(self, log):
        m = getattr(self._miner, "masker", None)
        return m.mask(log) if m else log
    def parse(self, lines, sample_limit=SAMPLE_RECORDS):
        records, total_lines, total_params, new_clusters = [], 0, 0, 0
        for raw in lines:
            log = raw.rstrip("\n")
            if not log.strip(): continue
            res = self._miner.add_log_message(log)
            template = res["template_mined"]
            params = _extract_parameters(template, self._mask(log))
            total_lines += 1; total_params += len(params)
            if res["change_type"] == "new": new_clusters += 1
            if len(records) < sample_limit:
                records.append(ParsedRecord(log, res["cluster_id"], template, params, res["change_type"]))
        clusters = sorted(
            [ClusterInfo(c.cluster_id, c.size, c.get_template()) for c in self._miner.drain.id_to_cluster.values()],
            key=lambda c: c.size, reverse=True)
        result = ParseResult(self.name, records, clusters)
        result._total_lines = total_lines
        result._total_params = total_params
        result._new_clusters = new_clusters
        return result
