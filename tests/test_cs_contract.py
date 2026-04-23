#!/usr/bin/env python3
"""
Contract test: verify every CS endpoint used by cortex still exists
in the published consciousness-server.

Run locally:
    CS_URL=http://127.0.0.1:3032 python3 tests/test_cs_contract.py

CI:
    .github/workflows/cs-contract.yml starts a fresh CS docker stack
    in AUTH_MODE=off and points CS_URL at it. The workflow also runs
    on a nightly cron, so a CS-side route refactor gets caught even
    when cortex itself has not been touched.

Why this test exists
--------------------
Cortex and consciousness-server are separate repos. When CS refactors
its route table (e.g. POST /api/tasks -> POST /api/tasks/create during
the v0.1.x audit rounds, GET /api/agents/:name/briefing -> GET
/api/briefing/:agent), cortex's hardcoded paths silently start 404'ing.
This test catches the mismatch the moment it lands on either side.

Next step: replace with a client generated from a CS-published OpenAPI
spec, so route names come from one source of truth instead of two.
"""
import os
import sys

import requests

CS_URL = os.environ.get("CS_URL", "http://127.0.0.1:3032")
AGENT = "CONTRACT_TEST"
TASK_ID_PLACEHOLDER = "00000000-0000-0000-0000-000000000000"

# (method, path, description). The set mirrors every distinct CS URL
# referenced in agent.py and worker.py — keep them in sync.
ENDPOINTS = [
    ("POST",  "/api/agents/register",                         "agent registration"),
    ("POST",  f"/api/agents/{AGENT}/heartbeat",               "heartbeat"),
    ("PATCH", f"/api/agents/{AGENT}/status",                  "status update"),
    ("GET",   f"/api/briefing/{AGENT}",                       "briefing"),
    ("POST",  "/api/memory/conversations",                    "conversation persist"),
    ("POST",  "/api/notes",                                   "note create"),
    ("POST",  "/api/tasks/create",                            "task create"),
    ("GET",   f"/api/tasks/pending/{AGENT}",                  "pending tasks"),
    ("GET",   f"/api/tasks/{TASK_ID_PLACEHOLDER}",            "task get"),
    ("PATCH", f"/api/tasks/{TASK_ID_PLACEHOLDER}/status",     "task status update"),
]


def route_exists(method: str, path: str) -> tuple[bool, str]:
    # A route exists if CS returns JSON — even a 400/404 with a JSON
    # error body proves the handler fired. An Express default 404
    # ("Cannot GET /xxx") comes back as text/html and means no route.
    try:
        r = requests.request(method, f"{CS_URL}{path}", json={}, timeout=5)
    except requests.RequestException as exc:
        return False, f"network error: {exc}"

    content_type = r.headers.get("Content-Type", "")
    if "application/json" in content_type:
        return True, f"HTTP {r.status_code} JSON"
    body_sample = r.text[:160].replace("\n", " ")
    return False, f"HTTP {r.status_code} non-JSON: {body_sample}"


def main() -> int:
    try:
        h = requests.get(f"{CS_URL}/health", timeout=5)
        h.raise_for_status()
    except Exception as exc:
        print(f"[FATAL] {CS_URL}/health unreachable: {exc}", file=sys.stderr)
        return 2

    print(f"CS_URL={CS_URL} — verifying {len(ENDPOINTS)} endpoints")
    failures = []
    for method, path, desc in ENDPOINTS:
        ok, detail = route_exists(method, path)
        mark = " OK " if ok else "FAIL"
        print(f"  [{mark}] {method:5s} {path:50s} {detail}  ({desc})")
        if not ok:
            failures.append((method, path, desc, detail))

    if failures:
        print(f"\n{len(failures)}/{len(ENDPOINTS)} contract mismatch — "
              "cortex will break on these routes")
        return 1
    print(f"\nAll {len(ENDPOINTS)} endpoints present.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
