"""Runs the dataset, attributes failures to a stage, writes a report.

    python3 -m evals.runner                          # 1 run, deterministic
    python3 -m evals.runner --runs 20                # 20 runs per case
    TEMP=0.3 python3 -m evals.runner --runs 20       # ...with a stochastic agent
    python3 -m evals.runner --json reports/run.json
    BUGS=retrieval_ignores_city python3 -m evals.runner

Exit code is 1 if any deterministic assertion fails, so this works as a CI gate.
Judge scores are reported but do not fail the build — see judge.py for why.

ON RUNNING MORE THAN ONCE
-------------------------
At TEMP=0 the agent is a lookup table: one run tells you everything, and
--runs 20 just prints the same answer twice as slowly.

At TEMP>0 one run tells you almost nothing. A case that passes once may pass
30% of the time, and a suite that is green today can be red tomorrow with no
code change at all. The number you actually want is not "did it pass" but
"what fraction of the time does it pass, and how sure am I of that fraction".

Two different uncertainties get confused constantly, so this reports them
separately:

  run-to-run variance   Same dataset, same code, different sampling. Measured
                        directly: run the whole suite r times, look at the
                        spread of the r pass rates. This is the one that makes
                        CI flaky.

  dataset uncertainty   You measured 26 cases, but you care about the whole
                        input space. A confidence interval on the pass rate
                        addresses this — it is the "±" you should quote when
                        someone asks whether a change made things better.

A single number with neither is a number with unknown error bars.
"""

import argparse
import json
import math
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent import agent, noise                # noqa: E402
from evals import assertions, judge           # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DATASET = os.path.join(HERE, "dataset.json")

STAGE_ORDER = ["routing", "retrieval", "tool_call", "generation"]

# Was 3, which passed an answer missing HALF the content its rubric required
# (score = 1 + round(ratio*4) returns 3 at ratio 0.5). 4 means "at least three
# quarters of the required content is present".
JUDGE_THRESHOLD = 4


def attribute(results):
    """Blame the EARLIEST failing stage, not the loudest one.

    If retrieval returns the wrong documents, generation will also look wrong.
    Reporting both is noise: the generator did its job faithfully with bad
    input. Attributing to the earliest broken stage is what turns "the answer
    was wrong" into a ticket someone can pick up.
    """
    failed = [r for r in results if not r.passed]
    if not failed:
        return None
    return min(failed, key=lambda r: STAGE_ORDER.index(r.stage)).stage


def wilson(k, n, z=1.96):
    """95% confidence interval for a proportion, Wilson score method.

    Not the textbook p ± z*sqrt(p(1-p)/n). That normal approximation breaks
    exactly where eval suites live: small n and proportions near 0 or 1. At
    26/26 it produces the interval [1.0, 1.0] — "we are certain this system
    never fails", from 26 observations. Wilson gives [0.87, 1.00], which is
    the honest statement: you have seen no failures, and you have not seen
    enough to rule them out.
    """
    if n == 0:
        return 0.0, 0.0
    p = k / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return max(0.0, centre - half), min(1.0, centre + half)


def run_once(case, j, seed, run_index):
    rng = noise.rng_for(seed, case["id"], run_index) if noise.TEMP > 0 else None
    text, trace = agent.run(case["query"], rng=rng)
    results = assertions.run_all(case, text, trace)
    score, reason = j.score(case, text, trace)
    blame = attribute(results)
    return {
        "run": run_index,
        "answer": text,
        "passed": blame is None,
        "blamed_stage": blame,
        "judge_score": score,
        "judge_reason": reason,
        "checks": [{"name": r.name, "stage": r.stage, "passed": r.passed,
                    "detail": r.detail, "meta": r.meta} for r in results],
        "trace": trace.as_dict(),
    }


def run(dataset_path=DATASET, runs=1, seed=None):
    with open(dataset_path, encoding="utf-8") as f:
        cases = json.load(f)["cases"]

    j = judge.get_judge()
    rows = []

    for case in cases:
        attempts = [run_once(case, j, seed, i) for i in range(runs)]
        n_pass = sum(a["passed"] for a in attempts)

        if n_pass == runs:
            verdict = "pass"
        elif n_pass == 0:
            verdict = "fail"
        else:
            verdict = "flaky"          # the state a single run cannot report

        blames = Counter(a["blamed_stage"] for a in attempts if a["blamed_stage"])

        rows.append({
            "id": case["id"],
            "group": case.get("group", ""),
            "query": case["query"],
            "runs": runs,
            "passes": n_pass,
            "pass_rate": n_pass / runs,
            "verdict": verdict,
            "blamed_stages": dict(blames),
            "judge_scores": [a["judge_score"] for a in attempts],
            # Keep one representative attempt for the detail report, preferring
            # a failing one — a failure is the interesting artefact.
            "sample": next((a for a in attempts if not a["passed"]), attempts[0]),
            "attempts": attempts,
        })

    return rows, j.name


def summarise(rows, judge_name, runs):
    total_cases = len(rows)
    stable_pass = [r for r in rows if r["verdict"] == "pass"]
    flaky = [r for r in rows if r["verdict"] == "flaky"]
    stable_fail = [r for r in rows if r["verdict"] == "fail"]

    observations = total_cases * runs
    successes = sum(r["passes"] for r in rows)
    lo, hi = wilson(successes, observations)

    # Run-to-run spread: the pass rate of each COMPLETE pass over the dataset.
    # This is what a CI job would have printed on run i.
    per_run = []
    for i in range(runs):
        per_run.append(sum(r["attempts"][i]["passed"] for r in rows) / total_cases)
    mean = sum(per_run) / len(per_run)
    sd = (sum((x - mean) ** 2 for x in per_run) / len(per_run)) ** 0.5

    blame = Counter()
    for r in rows:
        for stage, n in r["blamed_stages"].items():
            blame[stage] += n

    prec, rec = [], []
    for r in rows:
        for a in r["attempts"]:
            for c in a["checks"]:
                if c["name"] == "retrieval" and "precision" in c["meta"]:
                    prec.append(c["meta"]["precision"])
                    rec.append(c["meta"]["recall"])

    by_group = defaultdict(lambda: {"cases": 0, "passes": 0, "obs": 0, "flaky": 0})
    for r in rows:
        g = by_group[r["group"]]
        g["cases"] += 1
        g["passes"] += r["passes"]
        g["obs"] += r["runs"]
        g["flaky"] += r["verdict"] == "flaky"
    for g in by_group.values():
        g["rate"] = g["passes"] / g["obs"] if g["obs"] else 0
        g["lo"], g["hi"] = wilson(g["passes"], g["obs"])

    low_judge = sum(1 for r in rows for s in r["judge_scores"] if s < JUDGE_THRESHOLD)

    return {
        "generated": datetime.now().isoformat(timespec="seconds"),
        "bugs_enabled": sorted(agent.BUGS) or None,
        "temp": noise.TEMP,
        "judge": judge_name,
        "runs_per_case": runs,
        "cases": total_cases,
        "observations": observations,
        "stable_pass": len(stable_pass),
        "flaky": len(flaky),
        "stable_fail": len(stable_fail),
        "task_success_rate": round(successes / observations, 4),
        "ci95": [round(lo, 4), round(hi, 4)],
        "per_run_rates": [round(x, 4) for x in per_run],
        "per_run_mean": round(mean, 4),
        "per_run_sd": round(sd, 4),
        "per_run_min": round(min(per_run), 4),
        "per_run_max": round(max(per_run), 4),
        "failures_by_stage": dict(blame),
        "retrieval_precision": round(sum(prec) / len(prec), 3) if prec else None,
        "retrieval_recall": round(sum(rec) / len(rec), 3) if rec else None,
        "judge_below_threshold": low_judge,
        "by_group": {k: dict(v) for k, v in by_group.items()},
    }


def print_report(rows, summary):
    w = sys.stdout.write
    runs = summary["runs_per_case"]
    w("\n" + "=" * 74 + "\n")
    w("LLM EVALUATION REPORT\n")
    w("=" * 74 + "\n")
    if summary["bugs_enabled"]:
        w(f"BUGS ENABLED: {', '.join(summary['bugs_enabled'])}\n")
    w(f"judge: {summary['judge']}   TEMP: {summary['temp']}   "
      f"cases: {summary['cases']} x {runs} runs = {summary['observations']} observations\n")
    w(f"stable pass: {summary['stable_pass']}   "
      f"FLAKY: {summary['flaky']}   stable fail: {summary['stable_fail']}\n")

    lo, hi = summary["ci95"]
    w(f"\ntask success rate: {summary['task_success_rate']:.1%}   "
      f"95% CI [{lo:.1%}, {hi:.1%}]\n")

    if runs > 1:
        w(f"per-run spread:    mean {summary['per_run_mean']:.1%}   "
          f"sd {summary['per_run_sd']:.1%}   "
          f"min {summary['per_run_min']:.1%}   max {summary['per_run_max']:.1%}\n")
        w("                   ^ same code, same dataset. This is what CI would\n"
          "                     have printed on each of those runs.\n")

    if summary["retrieval_precision"] is not None:
        w(f"\nretrieval precision: {summary['retrieval_precision']:.3f}   "
          f"recall: {summary['retrieval_recall']:.3f}\n")

    if summary["failures_by_stage"]:
        w("\nFAILURES BY STAGE (earliest broken stage, counted over all observations)\n")
        for stage in STAGE_ORDER:
            n = summary["failures_by_stage"].get(stage)
            if n:
                w(f"  {stage:12} {n}\n")

    w("\nBY GROUP" + ("  (rate with 95% CI)" if runs > 1 else "") + "\n")
    for g, v in sorted(summary["by_group"].items()):
        mark = "ok  " if v["rate"] == 1.0 else "FAIL"
        line = f"  [{mark}] {g:26} {v['rate']:6.1%}"
        if runs > 1:
            line += f"  [{v['lo']:.0%}, {v['hi']:.0%}]"
            if v["flaky"]:
                line += f"   {v['flaky']} flaky"
        w(line + "\n")

    flaky = [r for r in rows if r["verdict"] == "flaky"]
    if flaky:
        w(f"\nFLAKY CASES ({len(flaky)}) — pass sometimes. A single run reports\n"
          "these as either green or red, and both are lies.\n" + "-" * 74 + "\n")
        for r in sorted(flaky, key=lambda r: r["pass_rate"]):
            stages = ", ".join(f"{k}x{v}" for k, v in r["blamed_stages"].items())
            w(f"  {r['id']:14} {r['passes']:>3}/{r['runs']}  "
              f"{r['pass_rate']:5.0%}  [{stages}]  {r['query'][:44]!r}\n")

    failures = [r for r in rows if r["verdict"] == "fail"]
    if failures:
        w(f"\nSTABLE FAILURES ({len(failures)})\n" + "-" * 74 + "\n")
        for r in failures:
            s = r["sample"]
            w(f"\n  {r['id']}  [{s['blamed_stage']}]  {r['query']!r}\n")
            for c in s["checks"]:
                if not c["passed"]:
                    w(f"     x {c['name']}: {c['detail']}\n")
            w(f"     answer: {s['answer'][:140]}\n")

    if summary["judge_below_threshold"]:
        w(f"\njudge below threshold ({JUDGE_THRESHOLD}/5): "
          f"{summary['judge_below_threshold']} of {summary['observations']} "
          "observations — warning only, does not fail the build\n")

    w("\n" + "=" * 74 + "\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", help="write the full report to this path")
    ap.add_argument("--dataset", default=DATASET)
    ap.add_argument("--runs", type=int, default=1,
                    help="runs per case. >1 is only meaningful when TEMP>0")
    ap.add_argument("--seed", default=None,
                    help="seed for reproducible stochastic runs")
    ap.add_argument("--gate", choices=["strict", "lower-bound"], default="strict",
                    help="strict: any non-pass fails. "
                         "lower-bound: fail if the CI lower bound is under --min-rate")
    ap.add_argument("--min-rate", type=float, default=0.95)
    args = ap.parse_args()

    rows, judge_name = run(args.dataset, runs=args.runs, seed=args.seed)
    summary = summarise(rows, judge_name, args.runs)
    print_report(rows, summary)

    if args.json:
        os.makedirs(os.path.dirname(args.json) or ".", exist_ok=True)
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump({"summary": summary, "cases": rows}, f, indent=2)
        print(f"wrote {args.json}")

    if args.gate == "lower-bound":
        lo = summary["ci95"][0]
        ok = lo >= args.min_rate
        print(f"gate=lower-bound: CI lower bound {lo:.1%} "
              f"{'>=' if ok else '<'} required {args.min_rate:.1%} "
              f"-> {'PASS' if ok else 'FAIL'}")
        return 0 if ok else 1

    return 1 if (summary["stable_fail"] or summary["flaky"]) else 0


if __name__ == "__main__":
    sys.exit(main())
