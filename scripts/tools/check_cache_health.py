#!/usr/bin/env python3
#
# Copyright (c) 2026 Project CHIP Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Measure ccache restore outcomes over recent default-branch runs.

Inventory is reported but never alarms. A key missing from a point-in-time listing is
routine here: entries are evicted under quota pressure and rewritten by the next run,
so absence is a phase of a cycle rather than an incident, and alarming on it produces a
permanently red job. What degrades build time is the restore *missing* when a job asks
for it, which is only visible across runs.

Covers the GitHub Actions cache quota only. BuildJet and Namespace cache volumes serve
other caches and are invisible to this endpoint.
"""

import argparse
import json
import os
import re
import subprocess
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone

GIB = 1024 ** 3
GB = 10 ** 9

RESTORED = re.compile(r"Cache restored from key: (\S+)")
MISSED = re.compile(r"Cache not found for input keys: ([^,\s]+)")


def gh(*args: str) -> str:
    return subprocess.run(["gh", *args], capture_output=True, text=True, check=True).stdout


def fetch_caches(repository: str) -> list[dict]:
    out = gh("api", "--paginate", f"repos/{repository}/actions/caches?per_page=100",
             "--jq", ".actions_caches[]")
    return [json.loads(line) for line in out.splitlines() if line.strip()]


def fetch_runs(repository: str, workflow: str, branch: str, since: datetime,
               cap: int) -> list[dict]:
    """Completed runs newer than `since`, so workflows of different cadence share a window.

    A run-count limit would reach back hours on a per-push workflow and weeks on a nightly
    one, and averaging those produces a rate with no meaningful period.
    """
    out = gh("api", f"repos/{repository}/actions/workflows/{workflow}/runs"
                    f"?branch={branch}&status=completed&per_page={cap}",
             "--jq", ".workflow_runs[] | {id, created_at}")
    runs = [json.loads(line) for line in out.splitlines() if line.strip()]
    return [r for r in runs
            if datetime.fromisoformat(r["created_at"].replace("Z", "+00:00")) >= since]


def fetch_job_log(repository: str, job_id: int) -> str:
    try:
        return gh("api", f"repos/{repository}/actions/jobs/{job_id}/logs",
                  "--allow-escape-sequences")
    except subprocess.CalledProcessError:
        return ""


def outcomes(repository: str, runs: list[dict], job_pattern: re.Pattern,
             results: dict[str, list[bool]] | None = None) -> dict[str, list[bool]]:
    """Map each cache key to the hit/miss result of every restore that asked for it."""
    results = defaultdict(list) if results is None else results
    for run in runs:
        jobs = gh("api", f"repos/{repository}/actions/runs/{run['id']}/jobs?per_page=100",
                  "--jq", ".jobs[] | {id, name}")
        for line in jobs.splitlines():
            job = json.loads(line)
            if not job_pattern.search(job["name"]):
                continue
            log = fetch_job_log(repository, job["id"])
            for key in RESTORED.findall(log):
                results[key].append(True)
            for key in MISSED.findall(log):
                results[key].append(False)
    return results


def age_hours(timestamp: str) -> float:
    parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    return (datetime.now(timezone.utc) - parsed).total_seconds() / 3600


def render_inventory(caches: list[dict], cap_gib: float) -> str:
    total = sum(entry["size_in_bytes"] for entry in caches)
    lines = [
        "## Cache inventory (report only)",
        "",
        f"**{total / GIB:.2f} GiB** ({total / GB:.2f} GB) across **{len(caches)} entries**, "
        f"cap {cap_gib:g} GiB.",
        "",
        "| GiB | ref | key | age (h) | idle (h) |",
        "|---:|---|---|---:|---:|",
    ]
    for entry in sorted(caches, key=lambda c: c["size_in_bytes"], reverse=True):
        lines.append(
            f"| {entry['size_in_bytes'] / GIB:.2f} | {entry['ref']} | `{entry['key']}` | "
            f"{age_hours(entry['created_at']):.1f} | {age_hours(entry['last_accessed_at']):.1f} |")
    pr_scoped = [e for e in caches if e["ref"].startswith("refs/pull/")]
    if pr_scoped:
        lines += ["", "Pull-request-scoped entries, readable by one PR and nothing else:", ""]
        lines += [f"- `{e['key']}` on {e['ref']}" for e in pr_scoped]
    return "\n".join(lines)


def render_rates(results: dict[str, list[bool]], runs: list[dict], threshold: float,
                 workflows: list[str]) -> str:
    window = ""
    if runs:
        window = (f" Window: {runs[-1]['created_at'][:16]} to {runs[0]['created_at'][:16]}, "
                  f"{len(runs)} runs across {len(workflows)} workflows.")
    lines = [
        "", "## Cache restore outcomes", "",
        f"Miss rate per key over the sampled window; alarm threshold {threshold:.0%}.{window}",
        "", "| key | restores (n) | misses | miss rate |", "|---|---:|---:|---:|",
    ]
    for key, seen in sorted(results.items()):
        misses = seen.count(False)
        lines.append(f"| `{key}` | {len(seen)} | {misses} | {misses / len(seen):.0%} |")
    if not results:
        lines.append("| _no restores observed_ | 0 | 0 | — |")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY"))
    parser.add_argument("--workflow", action="append", default=[],
                        help="Workflow file to sample; repeatable. Every workflow whose "
                             "jobs restore a cache must be listed or its keys go unmeasured.")
    parser.add_argument("--branch", default="master")
    parser.add_argument("--since-days", type=float, default=3.0,
                        help="Sample runs started within this many days.")
    parser.add_argument("--max-runs-per-workflow", type=int, default=20)
    parser.add_argument("--job-pattern", default="Test Suites|REPL Tests")
    parser.add_argument("--miss-threshold", type=float, default=0.25)
    parser.add_argument("--min-samples", type=int, default=5,
                        help="Restores a key needs before its rate can alarm.")
    parser.add_argument("--cap-gib", type=float, default=10.0)
    parser.add_argument("--summary-file")
    parser.add_argument("--alarm-file")
    args = parser.parse_args()

    if not args.repository:
        print("error: --repository or GITHUB_REPOSITORY is required", file=sys.stderr)
        return 2

    caches = fetch_caches(args.repository)
    pattern = re.compile(args.job_pattern)
    workflows = args.workflow or ["tests.yaml", "nightly.yaml", "darwin-tests.yaml"]
    since = datetime.now(timezone.utc) - timedelta(days=args.since_days)
    runs: list[dict] = []
    results: dict[str, list[bool]] = defaultdict(list)
    for workflow in workflows:
        sampled = fetch_runs(args.repository, workflow, args.branch, since,
                             args.max_runs_per_workflow)
        runs += sampled
        outcomes(args.repository, sampled, pattern, results)
    runs.sort(key=lambda r: r["created_at"], reverse=True)

    report = render_inventory(caches, args.cap_gib) + "\n" + render_rates(
        results, runs, args.miss_threshold, workflows)
    print(report)
    if args.summary_file:
        with open(args.summary_file, "a") as handle:
            handle.write(report)

    degraded = [
        f"{key} {seen.count(False)}/{len(seen)} misses ({seen.count(False) / len(seen):.0%})"
        for key, seen in sorted(results.items())
        if len(seen) >= args.min_samples and seen.count(False) / len(seen) > args.miss_threshold]
    if not degraded:
        return 0

    alarm = f"cache miss rate over {len(runs)} {args.branch} runs: {'; '.join(degraded)}"
    print(f"::error::{alarm}")
    if args.alarm_file:
        with open(args.alarm_file, "w") as handle:
            handle.write(alarm + "\n")
    return 1


if __name__ == "__main__":
    sys.exit(main())
