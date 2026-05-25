# drain3 log parser — web app

Upload a log file in the browser, get it clustered and parsed by drain3.
The parsing backend is pluggable: swapping drain3 for "drain3 + LLM" later
is a one-file + one-line change. No server code changes.

## Layout
    pure_drain/
      drain3.ini                     masking config (already yours)
      webapp/
        server.py                    FastAPI app — backend-agnostic
        parsers/
          base.py                    LogParser interface (the swap seam)
          drain3_parser.py           drain3 backend
          registry.py                backend registry — swap engines HERE
        static/
          index.html                 frontend (single file)

## Run
    pip install -r requirements.txt
    cd pure_drain                     # must run from here so drain3.ini is found
    uvicorn webapp.server:app --reload
    # open http://localhost:8000

## Swapping the backend (drain3 -> drain3 + LLM)
1. Create webapp/parsers/drain3_llm_parser.py:

       from .base import LogParser, ParseResult
       class Drain3LLMParser(LogParser):
           name = "drain3_llm"
           def parse(self, lines) -> ParseResult:
               ...   # drain3 first, then LLM refines templates

2. Register it in webapp/parsers/registry.py:

       from .drain3_llm_parser import Drain3LLMParser
       _REGISTRY = {
           "drain3":     Drain3Parser,
           "drain3_llm": Drain3LLMParser,
       }

3. Select it:  export PARSER_BACKEND=drain3_llm   (or pick it in the UI dropdown)

server.py never changes — it only ever calls registry.get_parser().
