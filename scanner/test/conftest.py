"""CPython test setup: stubs Pyodide-only `workers`; vendored src/atif-scan must shadow the parity group's copy."""

import asyncio
import json
import sys
import types
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(SRC))

stub = types.ModuleType("workers")


class WorkerEntrypoint:  # minimal stand-in for workers.WorkerEntrypoint
    def __init__(self, ctx=None, env=None):
        self.ctx, self.env = ctx, env


class Response:  # minimal stand-in for workers.Response
    def __init__(self, body="", status=200, headers=None):
        self.body, self.status, self.headers = body, status, headers or {}


stub.WorkerEntrypoint = WorkerEntrypoint
stub.Response = Response
sys.modules["workers"] = stub

import atif_scan  # noqa: E402

assert Path(atif_scan.__file__).resolve().is_relative_to(SRC), atif_scan.__file__

import entry  # noqa: E402


def scan(steps, calls):
    """Run Worker B's RPC method as the proxy would: one JSON string in, one out."""
    raw = asyncio.run(entry.Default().scan(json.dumps({"steps": steps, "calls": calls})))
    return json.loads(raw)["findings"]


def bash(command):
    return {"name": "Bash", "arguments": {"command": command}}


@pytest.fixture
def run_scan():
    return scan
