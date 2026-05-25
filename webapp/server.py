"""
FastAPI server — upload a log file, get it parsed and clustered.

Run from the pure_drain folder so drain3.ini is found:

    uvicorn webapp.server:app --reload

Then open  http://localhost:8000

The server is backend-agnostic: it calls webapp.parsers.registry.get_parser()
and never imports drain3 itself. Swapping engines is done in registry.py.
"""
from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse

from .parsers.registry import active_backend, available_backends, get_parser

app = FastAPI(title="drain3 log parser")

STATIC = Path(__file__).parent / "static"

# cap per-line records shipped to the browser; stats/clusters stay complete
RECORD_LIMIT = 500
# refuse absurdly large uploads (bytes)
MAX_UPLOAD = 50 * 1024 * 1024


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return (STATIC / "index.html").read_text(encoding="utf-8")


@app.get("/api/backends")
def backends() -> dict:
    """List parsing backends and which one is active."""
    return {"available": available_backends(), "active": active_backend()}


@app.post("/api/parse")
async def parse(
    file:    UploadFile = File(...),
    backend: str | None = Form(default=None),
) -> JSONResponse:
    """Parse an uploaded log file and return clusters + per-line records."""
    raw = await file.read()
    if not raw:
        raise HTTPException(400, "file is empty")
    if len(raw) > MAX_UPLOAD:
        raise HTTPException(413, f"file exceeds {MAX_UPLOAD // 1024 // 1024} MB limit")

    text  = raw.decode("utf-8", errors="replace")
    lines = text.splitlines()
    if not any(ln.strip() for ln in lines):
        raise HTTPException(400, "file has no non-blank lines")

    try:
        parser = get_parser(backend or None)
    except ValueError as e:
        raise HTTPException(400, str(e))

    result = parser.parse(lines)
    payload = result.to_dict(record_limit=RECORD_LIMIT)
    payload["filename"] = file.filename
    return JSONResponse(payload)
