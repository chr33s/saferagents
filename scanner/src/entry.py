"""atif-scan over a trimmed ATIF trace; mirrors safeagents.scan.Scanner.signals."""

import json

from workers import Response, WorkerEntrypoint

from atif_scan import CheckSpec, Context, Engine, RegexDetector, Severity, builtin_detectors, parse_trace
from atif_scan.access import access_rules
from atif_scan.data.model import Channel
from atif_scan.detectors.priming import builtin_allowances
from gapfill import GAP_FILL_DETECTORS

ATIF_SCHEMA_VERSION = "ATIF-v1.7"
TRACE_QUALITY = "integrity."

# Verbatim from safeagents.scan.EXTRA_DETECTORS.
EXTRA_DETECTORS = (
    RegexDetector(
        CheckSpec("safeagents.namespace_escape", Severity.MEDIUM, title="Creates or enters Linux namespaces"),
        r"\b(?:unshare|nsenter)\b",
        frozenset({Channel.COMMAND}),
    ),
)

# Built at import so the memory snapshot captures it.
ENGINE = Engine([*builtin_detectors(), *access_rules(), *builtin_allowances(), *EXTRA_DETECTORS, *GAP_FILL_DETECTORS])


def pending_step(calls: list[dict]) -> dict:
    return {
        "source": "agent",
        "message": "",
        "tool_calls": [
            {"tool_call_id": f"pending-{i}", "function_name": c["name"], "arguments": c["arguments"]}
            for i, c in enumerate(calls)
        ],
    }


class Default(WorkerEntrypoint):
    async def fetch(self, request):
        # Required: Cloudflare rejects a Worker without an event handler, even an RPC-only one.
        return Response("not found", status=404)

    async def scan(self, request_json: str) -> str:
        # No try/except: an exception rejects the RPC and the proxy applies SCANNER_FAIL_MODE.
        req = json.loads(request_json)
        calls = req["calls"]
        if not calls:
            raise ValueError("no calls")
        trace_steps = [*req["steps"], pending_step(calls)]
        last_step, last_call = len(trace_steps) - 1, len(calls) - 1
        trace = parse_trace(
            {
                "schema_version": ATIF_SCHEMA_VERSION,
                "steps": [{"step_id": i + 1, **s} for i, s in enumerate(trace_steps)],
            }
        )
        findings = []
        for finding in ENGINE.evaluate(trace, Context()):
            spec = finding.spec
            if not finding.counts or spec.severity <= Severity.INFO or spec.id.startswith(TRACE_QUALITY):
                continue
            if any(e.step == last_step and e.call == last_call for e in finding.result.evidence):
                findings.append({"ruleId": spec.id, "severity": spec.severity.name.lower(), "title": spec.title})
        return json.dumps({"findings": findings})
