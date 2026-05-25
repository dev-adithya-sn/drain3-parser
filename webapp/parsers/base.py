"""
Pluggable log-parser interface.

This is the SWAP SEAM. The web server depends only on the abstractions in
this file — LogParser, ParsedRecord, ClusterInfo, ParseResult — and never
imports a concrete backend directly. Swapping drain3 for "drain3 + LLM"
later means writing one new file and editing one line in registry.py;
server.py does not change at all.

Contract every backend must honour:
  * implement LogParser.parse(lines) -> ParseResult
  * one ParsedRecord per non-blank input line
  * cluster_id is stable within a single parse() call
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass
from typing import Iterable


@dataclass
class ParsedRecord:
    """One parsed log line."""
    original_log: str
    cluster_id:   int
    template:     str
    parameters:   list[str]
    change_type:  str            # "new" | "cluster_template_changed" | "none"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ClusterInfo:
    """Summary of one discovered cluster."""
    cluster_id: int
    size:       int
    template:   str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ParseResult:
    """Everything a backend returns for one parsed file."""
    backend:  str
    records:  list[ParsedRecord]
    clusters: list[ClusterInfo]

    @property
    def stats(self) -> dict:
        return {
            "lines":            len(self.records),
            "clusters":         len(self.clusters),
            "params_extracted": sum(len(r.parameters) for r in self.records),
            "new_clusters":     sum(1 for r in self.records
                                    if r.change_type == "new"),
        }

    def to_dict(self, record_limit: int | None = None) -> dict:
        """
        Serialise for the API. record_limit caps how many per-line records
        are sent to the browser (stats and clusters are always complete);
        large uploads would otherwise ship a multi-MB payload and freeze
        the DOM.
        """
        recs = self.records if record_limit is None else self.records[:record_limit]
        return {
            "backend":       self.backend,
            "stats":         self.stats,
            "clusters":      [c.to_dict() for c in self.clusters],
            "records":       [r.to_dict() for r in recs],
            "records_total": len(self.records),
        }


class LogParser(ABC):
    """Base class for all log-parsing backends."""

    #: short identifier shown in the UI and used as the registry key
    name: str = "abstract"

    @abstractmethod
    def parse(self, lines: Iterable[str]) -> ParseResult:
        """Parse raw log lines into a ParseResult. Must be implemented."""
        raise NotImplementedError
