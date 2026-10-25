#!/usr/bin/env python3
"""Builds the Kernels workflow's report: the PR comment and the run summary.

Usage: kernel-report.py CURRENT_DIR [BASE_DIR]

Each directory holds the kernel-logs-* artifacts of one run, one per kernel
job: meta.json (version, channel, arch, status) and the `go test -v` output
of the normal build (test.log) and of the BPF_DEBUG build (test-debug.log).
BASE_DIR is the base branch's latest run: verifier costs are compared per
kernel series and arch, since a series' point release can differ between
the two runs.

Environment: RUN_URL (this run), and on a pull request BASE_REF (its base
branch) and BASE_RUN_URL (the base run, when one was found).
"""

import json
import os
import re
import sys
from pathlib import Path

MARKER = "<!-- kloak-kernels-report -->"
# BPF_COMPLEXITY_LIMIT_INSNS, and TestVerifierBudget's budget (half of it).
LIMIT = 1_000_000
BUDGET = 500_000
# A cost change is listed when it moves by at least this much: the count is
# deterministic for a kernel and an object, so smaller moves are real but
# rarely worth a look.
MIN_CHANGE_PCT = 1.0
MIN_CHANGE_INSNS = 100
MAX_CHANGES = 25
MAX_FAILED_TESTS = 5

RUN = re.compile(r"^=== RUN\s+(\S+)")
VERIFIED = re.compile(r"verified (\d+) instructions")
REJECTED = "the verifier rejected a program"
OVER_BUDGET = "is over the budget"
FAIL = re.compile(r"^--- FAIL: (\S+)")
PANIC = re.compile(r"^panic: (.*)")


def series(version):
    """'7.3-rc4' -> (7, 3)."""
    major, minor = re.findall(r"\d+", version)[:2]
    return int(major), int(minor)


class Log:
    """What a `go test -v` log of pkg/ebpf says."""

    def __init__(self, text):
        self.costs = {}  # program -> verified instructions
        self.rejected = set()
        self.over_budget = set()
        self.failed = []  # top-level tests, TestVerifierBudget aside
        self.panic = None
        prog = None
        for line in text.splitlines():
            if m := RUN.match(line):
                name = m[1]
                prog = name.split("/", 1)[1] if name.startswith("TestVerifierBudget/") else None
                continue
            if prog:
                if m := VERIFIED.search(line):
                    self.costs[prog] = int(m[1])
                if REJECTED in line:
                    self.rejected.add(prog)
                if OVER_BUDGET in line:
                    self.over_budget.add(prog)
            if (m := FAIL.match(line)) and m[1] != "TestVerifierBudget":
                self.failed.append(m[1])
            if (m := PANIC.match(line)) and not self.panic:
                self.panic = m[1]


def parse_log(path):
    return Log(path.read_text(errors="replace")) if path.exists() else None


def load(root):
    """Returns {(series, arch): job} for the artifacts under root."""
    jobs = {}
    if not root or not Path(root).is_dir():
        return jobs
    for meta in sorted(Path(root).glob("**/meta.json")):
        job = json.loads(meta.read_text())
        job["normal"] = parse_log(meta.parent / "test.log")
        job["debug"] = parse_log(meta.parent / "test-debug.log")
        jobs[(series(job["version"]), job["arch"])] = job
    return jobs


def costs(job):
    return job["normal"].costs if job and job["normal"] else {}


def programs(job):
    """The programs a job verified or saw rejected (normal build)."""
    return costs(job).keys() | (job["normal"].rejected if job and job["normal"] else set())


def fmt(n):
    return f"{n:,}"


def cell(job, prog):
    if not job or not job["normal"]:
        return "—"
    log = job["normal"]
    if prog in log.rejected:
        return "❌ rejected"
    if prog not in log.costs:
        return "—"
    return ("⚠️ " if log.costs[prog] > BUDGET else "") + fmt(log.costs[prog])


def status_icon(job):
    if not job:
        return "—"
    if job["status"] == "success":
        return "✅"
    return "⚠️" if job["channel"] == "mainline" else "❌"


def failures(job):
    """One line on what failed in a job, or None."""
    parts = []
    for build in ("normal", "debug"):
        log = job[build]
        if not log:
            continue
        label = "" if build == "normal" else " (`BPF_DEBUG` build)"
        if log.rejected:
            parts.append(f"rejected{label}: " + ", ".join(f"`{p}`" for p in sorted(log.rejected)))
        if log.over_budget:
            parts.append(f"over the verifier budget{label}: " + ", ".join(f"`{p}`" for p in sorted(log.over_budget)))
        if log.failed:
            shown = ", ".join(f"`{t}`" for t in log.failed[:MAX_FAILED_TESTS])
            more = f" and {len(log.failed) - MAX_FAILED_TESTS} more" if len(log.failed) > MAX_FAILED_TESTS else ""
            parts.append(f"failed{label}: {shown}{more}")
        if log.panic:
            parts.append(f"{'go test' if build == 'normal' else 'the debug load'}: `{log.panic}`")
    if job["status"] != "success" and not parts:
        parts.append("the job failed before the tests ran (see its log)")
    return "; ".join(parts) or None


def main():
    current = load(sys.argv[1])
    base = load(sys.argv[2] if len(sys.argv) > 2 else None)
    # Only a pull request has a base to compare with.
    base_ref = os.environ.get("BASE_REF")
    run_url = os.environ.get("RUN_URL")
    base_url = os.environ.get("BASE_RUN_URL")

    kernels = sorted({k for k, _ in current}, reverse=True)
    arches = sorted({a for _, a in current}, key=lambda a: (a != "x86", a))
    out = [MARKER]

    if not current:
        out.append("### Kernels: no results\n\nNo kernel job uploaded its logs.")
        print("\n".join(out))
        return

    failed = [j for j in current.values() if j["status"] != "success" and j["channel"] != "mainline"]
    warned = [j for j in current.values() if j["status"] != "success" and j["channel"] == "mainline"]
    if failed:
        title = f"❌ {len(failed)} of {len(current)} kernel jobs failed"
    else:
        title = "✅ the BPF programs load on every kernel"
    if warned:
        title += " (mainline fails: a warning, not a failure)"
    out.append(f"### Kernels: {title}\n")
    run = f" ([run]({run_url}))" if run_url else ""
    out.append(
        "Each kernel boots in a VM. The BPF objects are loaded in both builds, normal and `BPF_DEBUG`. "
        f"Where the runner has KVM (x86), the `pkg/ebpf` tests run too.{run}\n"
    )

    # Kernel | x86 | arm64 | highest cost.
    out.append("| Kernel | " + " | ".join(arches) + " | Highest verifier cost |")
    out.append("|---|" + ":-:|" * len(arches) + "---|")
    for k in kernels:
        jobs = [current.get((k, a)) for a in arches]
        any_job = next(j for j in jobs if j)
        top = max(
            ((n, p, a) for a, j in zip(arches, jobs) for p, n in costs(j).items()),
            default=None,
        )
        top_cell = f"{fmt(top[0])} ({top[0] * 100 // LIMIT}% of the limit): `{top[1]}`, {top[2]}" if top else "—"
        name = f"{any_job['version']} ({any_job['channel']})"
        out.append(f"| {name} | " + " | ".join(status_icon(j) for j in jobs) + f" | {top_cell} |")
    out.append("")

    lines = []
    for k in kernels:
        for a in arches:
            job = current.get((k, a))
            if job and (why := failures(job)):
                lines.append(f"- **{job['version']} {a}**: {why}")
    if lines:
        out += lines + [""]

    # Changes against the base run.
    against = f"[`{base_ref}`]({base_url})" if base_url else f"`{base_ref}`"
    if not base_ref:
        pass
    elif not base:
        out.append(f"> [!NOTE]\n> No Kernels run of {against} to compare the verifier costs with.\n")
    else:
        changes = []
        for key, job in current.items():
            old = base.get(key)
            if not old:
                continue
            cur, prev = costs(job), costs(old)
            label = f"{job['version']} {key[1]}"
            if old["version"] != job["version"]:
                label += f" (was {old['version']})"
            for prog in sorted(programs(job) | programs(old)):
                before, after = cell(old, prog), cell(job, prog)
                if prog in cur and prog in prev:
                    delta = cur[prog] - prev[prog]
                    pct = delta * 100 / prev[prog] if prev[prog] else float("inf")
                    if abs(delta) >= MIN_CHANGE_INSNS and abs(pct) >= MIN_CHANGE_PCT:
                        changes.append((abs(pct), prog, label, before, after, f"{delta:+,} ({pct:+.1f}%)"))
                elif before != after:
                    # Rejected on one side, or a program added or removed:
                    # listed first.
                    note = "loads now" if prog in cur and before != "—" else ""
                    changes.append((float("inf"), prog, label, before, after, note))
        changes.sort(key=lambda c: (-c[0], c[1], c[2]))
        if not changes:
            out.append(f"No program's verifier cost moved by {MIN_CHANGE_PCT:g}% or more compared to {against}.\n")
        else:
            out.append(f"#### Verifier cost compared to {against}\n")
            out.append(f"| Program | Kernel | `{base_ref}` | This PR | Change |")
            out.append("|---|---|---:|---:|---:|")
            for _, prog, label, prev, cur, delta in changes[:MAX_CHANGES]:
                out.append(f"| `{prog}` | {label} | {prev} | {cur} | {delta} |")
            if len(changes) > MAX_CHANGES:
                out.append(f"\n…and {len(changes) - MAX_CHANGES} more.")
            out.append("")

    # Every program on every kernel.
    progs = sorted(set().union(*(programs(j) for j in current.values())))
    if progs:
        out.append(f"<details>\n<summary>Verified instructions per program ({' / '.join(arches)})</summary>\n")
        names = [next(j for (s, _), j in current.items() if s == k)["version"] for k in kernels]
        out.append("| Program | " + " | ".join(names) + " |")
        out.append("|---|" + "---:|" * len(kernels))
        for prog in progs:
            cells = [" / ".join(cell(current.get((k, a)), prog) for a in arches) for k in kernels]
            out.append(f"| `{prog}` | " + " | ".join(cells) + " |")
        out.append(f"\nThe kernel rejects a program above {fmt(LIMIT)}; `TestVerifierBudget` fails above {fmt(BUDGET)} (⚠️).\n")
        out.append("</details>")

    print("\n".join(out))


if __name__ == "__main__":
    main()
