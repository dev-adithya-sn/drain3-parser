"""
Backend registry — the SINGLE place to swap log-parsing engines.

╔══════════════════════════════════════════════════════════════════════╗
║  HOW TO ADD A NEW BACKEND  (e.g. drain3 + LLM)                         ║
║                                                                        ║
║  1. Create  webapp/parsers/drain3_llm_parser.py  with a class:         ║
║                                                                        ║
║        from .base import LogParser, ParseResult                        ║
║        class Drain3LLMParser(LogParser):                               ║
║            name = "drain3_llm"                                         ║
║            def parse(self, lines) -> ParseResult: ...                  ║
║                                                                        ║
║  2. Import it below and add ONE line to _REGISTRY.                      ║
║  3. Select it with an env var:   export PARSER_BACKEND=drain3_llm       ║
║                                                                        ║
║  server.py never changes — it only ever calls get_parser().            ║
╚══════════════════════════════════════════════════════════════════════╝
"""
from __future__ import annotations

import os

from .base import LogParser
from .drain3_parser import Drain3Parser
from .security_parser import SecurityParser

_REGISTRY: dict[str, type[LogParser]] = {
    "drain3":   Drain3Parser,
    "security": SecurityParser,
}

# NuLog requires torch — register only if available
try:
    from .nulog_parser import NuLogParser
    _REGISTRY["nulog"] = NuLogParser
except ImportError:
    pass  # torch not installed; nulog backend unavailable

DEFAULT_BACKEND = "security"


def available_backends() -> list[str]:
    """Names of all registered backends."""
    return sorted(_REGISTRY)


def active_backend() -> str:
    """The backend that will be used if none is explicitly requested."""
    return os.environ.get("PARSER_BACKEND", DEFAULT_BACKEND)


def get_parser(backend: str | None = None, **kwargs) -> LogParser:
    """
    Construct a parser. Resolution order:
      explicit `backend` arg  ->  $PARSER_BACKEND env var  ->  DEFAULT_BACKEND
    """
    name = backend or active_backend()
    if name not in _REGISTRY:
        raise ValueError(
            f"unknown backend {name!r}; available: {available_backends()}"
        )
    return _REGISTRY[name](**kwargs)
