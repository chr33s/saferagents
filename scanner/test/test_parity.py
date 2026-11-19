"""Parity against upstream saferagents at a pinned commit (§9.2), over >= 200 requests.

Skipped without the `parity` group (`uv sync --all-groups`) and `npm install` in proxy/.
1. TS buildTrace() equals upstream recent(history()) apart from the result cap.
2. Worker B findings equal upstream Scanner.signals() (gap-fill ids excluded); result-cap delta <= 1% of calls.
3. TS checkPolicy blocks a superset of upstream Policy.check; extras map to documented deviations.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from collections import Counter
from pathlib import Path

import pytest
from conftest import scan
from corpus import build_corpus, load_recorded

from gapfill import GAP_FILL_DETECTORS

upstream_scan = pytest.importorskip("safeagents.scan", reason="parity group not installed (uv sync --all-groups)")
upstream_policy = pytest.importorskip("safeagents.policy")

PROXY = Path(__file__).resolve().parents[2] / "proxy"
GAP_IDS = {d.spec.id for d in GAP_FILL_DETECTORS}
# Documented deviations (§3.2): strict provenance and allowlist, bare network-command
# targets, unresolved runtime targets, self-protection.
DOCUMENTED_EXTRA = {"STAGE1-UNTRUSTED-HOST", "STAGE1-UNRESOLVED-TARGET", "STAGE1-SELF-PROTECT"}
MAX_CAP_DELTA = 0.01


@pytest.fixture(scope="module")
def corpus(tmp_path_factory):
    items = build_corpus()
    assert len(items) >= 200
    return items


@pytest.fixture(scope="module")
def ts(corpus, tmp_path_factory):
    if not (PROXY / "node_modules").exists() or not shutil.which("node"):
        pytest.skip("proxy dependencies not installed (npm install)")
    path = tmp_path_factory.mktemp("parity") / "corpus.json"
    path.write_text(json.dumps([{"request": c["request"], "calls": c["calls"]} for c in corpus]))
    out = subprocess.run(
        ["node", "scripts/trace-dump.ts", str(path)], cwd=PROXY, capture_output=True, text=True, check=True, timeout=300
    )
    return json.loads(out.stdout)


@pytest.fixture(scope="module")
def upstream_scanner():
    return upstream_scan.Scanner()


def upstream_trace(request):
    return upstream_scan.recent(upstream_scan.history(request))


def sig_ids(signals):
    return sorted(s.id for s in signals)


def worker_ids(findings, *, drop_gap=True):
    return sorted(f["ruleId"] for f in findings if not (drop_gap and f["ruleId"] in GAP_IDS))


def calls_for_worker(calls):
    out = []
    for c in calls:
        tool_call = upstream_scan._tool_call("x", c["name"], c["args"])
        out.append({"name": c["name"], "arguments": tool_call["arguments"]})
    return out


def test_recorded_corpus_has_at_least_200_requests():
    recorded = load_recorded()
    assert len(recorded) >= 200, f"spec §9.2 needs >= 200 recorded requests, have {len(recorded)}"
    print(f"\nrecorded corpus: {len(recorded)} requests, {sum(len(r['calls']) for r in recorded)} tool calls")


def test_trace_equals_upstream_apart_from_result_cap(corpus, ts):
    capped_diffs = 0
    for item, out in zip(corpus, ts, strict=True):
        expected = upstream_trace(item["request"])
        assert out["traceUncapped"] == expected
        if out["trace"] != expected:
            capped_diffs += 1
            for got, want in zip(out["trace"], expected, strict=True):
                for r_got, r_want in zip(
                    got.get("observation", {}).get("results", []),
                    want.get("observation", {}).get("results", []),
                    strict=True,
                ):
                    assert r_got["content"] == r_want["content"][:2000]
    print(f"\ntrace parity: {len(corpus)} requests; {capped_diffs} differ only by the 2000-char result cap")


def test_worker_findings_equal_upstream_signals(corpus, ts, upstream_scanner):
    total = mismatched_capped = 0
    gap_only = Counter()
    for item, out in zip(corpus, ts, strict=True):
        steps_up = upstream_trace(item["request"])
        pairs = [(c["name"], c["args"]) for c in item["calls"]]
        worker_calls = calls_for_worker(item["calls"])
        for k in range(1, len(pairs) + 1):
            total += 1
            expected = sig_ids(upstream_scanner.signals(steps_up, pairs[:k]))
            uncapped = scan(out["traceUncapped"], worker_calls[:k])
            assert worker_ids(uncapped) == expected, (item["calls"][k - 1], expected, uncapped)
            for f in uncapped:
                if f["ruleId"] in GAP_IDS:
                    gap_only[f["ruleId"]] += 1
            # The trace the proxy really sends (result cap applied).
            if worker_ids(scan(out["trace"], worker_calls[:k])) != expected:
                mismatched_capped += 1
    rate = mismatched_capped / total
    print(
        f"\nscanner parity: {total} calls; result-cap delta {mismatched_capped} ({rate:.2%}); gap-fill additions {dict(gap_only)}"
    )
    assert rate <= MAX_CAP_DELTA, "result cap changes findings on more than 1% of calls: raise TRACE_MAX_RESULT_CHARS"


def test_policy_blocks_superset_of_upstream(corpus, ts):
    total = extra = 0
    extra_by_rule = Counter()
    for item, out in zip(corpus, ts, strict=True):
        policy = upstream_policy.Policy(item["request"])
        for call, ts_result in zip(item["calls"], out["policy"], strict=True):
            total += 1
            up = policy.check(call["name"], call["args"])
            if up is not None:
                assert ts_result["action"] in ("block", "suspicious"), (call, up, ts_result)
            elif ts_result["action"] != "pass":
                extra += 1
                extra_by_rule[ts_result["ruleId"]] += 1
                assert ts_result["ruleId"] in DOCUMENTED_EXTRA, (call, ts_result)
    print(f"\npolicy parity: {total} calls; {extra} extra TS blocks/suspicious by rule {dict(extra_by_rule)}")
