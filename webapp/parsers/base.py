from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from typing import Iterable

@dataclass
class ParsedRecord:
    original_log: str
    cluster_id:   int
    template:     str
    parameters:   list[str]
    change_type:  str
    def to_dict(self): return asdict(self)

@dataclass
class ClusterInfo:
    cluster_id: int
    size:       int
    template:   str
    def to_dict(self): return asdict(self)

@dataclass
class ParseResult:
    backend:  str
    records:  list[ParsedRecord]
    clusters: list[ClusterInfo]
    _total_lines:   int | None = field(default=None, repr=False)
    _total_params:  int | None = field(default=None, repr=False)
    _new_clusters:  int | None = field(default=None, repr=False)

    @property
    def stats(self):
        return {
            "lines":            self._total_lines  if self._total_lines is not None else len(self.records),
            "clusters":         len(self.clusters),
            "params_extracted": self._total_params if self._total_params is not None else sum(len(r.parameters) for r in self.records),
            "new_clusters":     self._new_clusters if self._new_clusters is not None else sum(1 for r in self.records if r.change_type == "new"),
        }

    def to_dict(self, record_limit=None):
        recs = self.records if record_limit is None else self.records[:record_limit]
        return {
            "backend":       self.backend,
            "stats":         self.stats,
            "clusters":      [c.to_dict() for c in self.clusters],
            "records":       [r.to_dict() for r in recs],
            "records_total": self._total_lines if self._total_lines is not None else len(self.records),
        }

class LogParser(ABC):
    name: str = "abstract"
    @abstractmethod
    def parse(self, lines: Iterable[str]) -> ParseResult:
        raise NotImplementedError
