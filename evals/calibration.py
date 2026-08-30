"""How good is the judge? And how good is the human?

    python3 -m evals.calibration

Three score sources, and every useful question is a comparison of two:

    truth    what the degradation in variants.py says the answer is worth
    human    blind labels from evals/label.py
    judge    the LLM-as-judge under test

    judge vs truth   does the judge detect the specific defect?
    judge vs human   does the judge share human taste?
    human vs truth   is the human a reliable rater?

STEP 0 IS VALIDATING THE REFERENCE, NOT THE RATER.
A variant carrying truth=2 for "a required fact is missing" is worthless if no
rubric ever required that fact. Score anyone against it and the report
confidently blames them for missing a defect that was never detectable. The
reference standard is the thing nobody questions, which is exactly why it is
checked first, out loud, using the same witnesses variants.py uses to refuse
to generate bad items in the first place.

Two versions of this check, and the difference is the lesson. The first
compared each variant to its original and flagged the byte-identical ones: it
caught 2 items. The second asks whether the variant EXHIBITS THE DEFECT ITS
SCORE CLAIMS: it catches 7 on the same data. Sameness was a proxy for the
property that actually mattered.

ON RAW AGREEMENT AND WHY KAPPA EXISTS
Raw agreement is the fraction of items two raters scored identically. It is
almost always flattering, because agreeing by luck is easy when the score
distribution is lopsided. Cohen's kappa subtracts the agreement you would
expect from two raters guessing with the same marginal frequencies:

    kappa = (observed - expected) / (1 - expected)

kappa = 1 is perfect, 0 is "no better than chance", negative is worse than
chance. Landis & Koch's rough bands: <0.20 slight, 0.21-0.40 fair,
0.41-0.60 moderate, 0.61-0.80 substantial, >0.80 almost perfect. Treat them
as vocabulary, not law.

Plain kappa treats every disagreement as equally bad, which is wrong for an
ordered 1-5 scale: scoring a 3 as a 2 is a quibble, scoring a 1 as a 5 is a
catastrophe. Quadratic weighted kappa penalises by squared distance, so it is
the honest number for ordinal rubrics. Both are reported; when they diverge,
the disagreements are concentrated at the extremes.
"""

import argparse
import json
from concurrent.futures import ThreadPoolExecutor
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evals import judge as judge_mod          # noqa: E402
from agent import agent                       # noqa: E402
from evals import variants                    # noqa: E402
from evals.variants import TRUTH              # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
LABELS = os.path.join(HERE, "labels.json")
DATASET = os.path.join(HERE, "dataset.json")

KINDS = ["original", "padded", "hedged", "omission", "wrong", "verbose_wrong"]


# --- statistics ------------------------------------------------------------

def kappa(a, b, weighted=False, categories=(1, 2, 3, 4, 5)):
    """Cohen's kappa between two equal-length score lists."""
    n = len(a)
    if n == 0:
        return float("nan")
    idx = {c: i for i, c in enumerate(categories)}
    k = len(categories)

    # Name the offending value. Indexing straight into `idx` raised a bare
    # KeyError three modules and one long API run away from whatever produced
    # the off-scale score, and "KeyError: 6" does not tell you which rater,
    # which item, or which of the two lists it came from. OpenAIJudge validates
    # its own output now; this is the backstop for labels.json and for any
    # future score source that has not learned to.
    observed = [[0] * k for _ in range(k)]
    for x, y in zip(a, b):
        if x not in idx or y not in idx:
            bad = x if x not in idx else y
            raise ValueError(
                f"score {bad!r} is not on the {list(categories)} scale defined "
                f"in evals/rubric.py. A rater that scores off-scale has not been "
                f"calibrated, it has been mis-parsed.")
        observed[idx[x]][idx[y]] += 1

    row = [sum(observed[i]) / n for i in range(k)]
    col = [sum(observed[i][j] for i in range(k)) / n for j in range(k)]

    def w(i, j):
        if not weighted:
            return 0.0 if i == j else 1.0
        return ((i - j) ** 2) / ((k - 1) ** 2)      # quadratic

    # Both po and pe are DISAGREEMENT here (w=0 on the diagonal), which makes
    # the weighted and unweighted formulas identical:
    #
    #   kappa = (Po_agree - Pe_agree) / (1 - Pe_agree)
    #         = ((1-po) - (1-pe)) / (1 - (1-pe))
    #         = 1 - po/pe
    #
    # Writing them as two different expressions is how the first version of
    # this function returned kappa = 1.36, which is impossible: kappa is
    # bounded above by 1. A statistic outside its own range is the cheapest
    # bug signal you will ever get — check the bounds before the meaning.
    po = sum(w(i, j) * observed[i][j] / n for i in range(k) for j in range(k))
    pe = sum(w(i, j) * row[i] * col[j] for i in range(k) for j in range(k))
    if pe == 0:
        return float("nan")
    return 1 - po / pe


def agreement(a, b, tolerance=0):
    if not a:
        return 0.0
    return sum(abs(x - y) <= tolerance for x, y in zip(a, b)) / len(a)


def pearson(xs, ys):
    n = len(xs)
    if n < 2:
        return float("nan")
    mx, my = sum(xs) / n, sum(ys) / n
    num = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    dx = sum((x - mx) ** 2 for x in xs) ** 0.5
    dy = sum((y - my) ** 2 for y in ys) ** 0.5
    return num / (dx * dy) if dx and dy else float("nan")


# --- data ------------------------------------------------------------------

def load():
    with open(LABELS, encoding="utf-8") as f:
        state = json.load(f)
    with open(DATASET, encoding="utf-8") as f:
        cases = {c["id"]: c for c in json.load(f)["cases"]}
    return state, cases


def validate_reference(items, cases):
    """Re-check reference data this module did not generate.

    Delegates to variants.validate — the same witnesses the generator uses to
    refuse bad variants. The generator makes them unconstructable; this makes
    them undeliverable. Defence in depth, because labels.json may predate the
    current witnesses (as it did: the byte-identical check here missed six
    items whose 'missing fact' no rubric ever required).
    """
    originals = {i["case_id"]: i["answer"] for i in items if i["kind"] == "original"}
    broken = []
    for it in items:
        if it["kind"] == "original":
            continue
        original = originals.get(it["case_id"])
        if original is None:
            continue
        reason = variants.validate(it["kind"], original, it["answer"],
                                   cases[it["case_id"]])
        if reason:
            broken.append({**it, "reason": reason})
    return {b["id"] for b in broken}, broken


def score_all(judge, items, order, cases, traces, repeat=1, workers=1):
    """Score every item `repeat` times. Returns (medians, self_consistency).

    CONCURRENCY. Every unit of work here is independent — item i repeat j does
    not depend on anything else — and each one is almost entirely spent waiting
    on a network round trip. Run sequentially, 324 calls at ~1.5s each is about
    eight minutes with the CPU idle throughout. There was never a throttle to
    remove; the cost was the queue.

    Ordering is preserved by indexing results rather than appending, so a
    parallel run and a sequential run produce byte-identical reports.

    nonce=j keeps each repeat cached separately. Cache on the prompt alone and
    repeats 2..N are served from repeat 1, so self-consistency reads 100% by
    construction — a property of the cache reported as a property of the model.
    """
    tasks = [(idx, lid, j) for idx, lid in enumerate(order) for j in range(repeat)]

    def one(task):
        idx, lid, j = task
        it = items[lid]
        score, _reason = judge.score(cases[it["case_id"]], it["answer"],
                                     traces[it["case_id"]], nonce=j)
        return idx, j, score

    scores = {}
    if workers > 1 and tasks:
        # Run the first call alone. OpenAIJudge probes temperature support on
        # its first request; letting N threads discover that simultaneously
        # wastes N calls instead of one.
        idx, j, sc = one(tasks[0])
        scores[(idx, j)] = sc
        if len(tasks) > 1:
            with ThreadPoolExecutor(max_workers=workers) as pool:
                for idx, j, sc in pool.map(one, tasks[1:]):
                    scores[(idx, j)] = sc
    else:
        for task in tasks:
            idx, j, sc = one(task)
            scores[(idx, j)] = sc

    per_item, stable = [], 0
    for idx in range(len(order)):
        runs = [scores[(idx, j)] for j in range(repeat)]
        per_item.append(sorted(runs)[len(runs) // 2])          # median of repeats
        stable += len(set(runs)) == 1
    if repeat < 2:
        return per_item, None
    # Self-consistency: share of items where every repeat gave the same score.
    # A judge that cannot reproduce its own verdict cannot be calibrated against
    # anything else; this number bounds every other number in the report.
    return per_item, stable / len(order)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--judges", default="heuristic",
                    help="comma-separated: " + ",".join(judge_mod.JUDGES))
    ap.add_argument("--repeat", type=int, default=1,
                    help="score each item N times to measure judge self-consistency")
    ap.add_argument("--yes", action="store_true", help="skip the cost confirmation")
    ap.add_argument("--workers", type=int, default=8,
                    help="concurrent judge requests (default 8). Each call is "
                         "almost all network wait, so this is close to a linear "
                         "speedup until the provider's rate limit bites. Use 1 "
                         "to rule concurrency out when debugging.")
    ap.add_argument("--allow-partial", action="store_true",
                    help="report even if some requested judges could not run. "
                         "Off by default: a comparison missing half its "
                         "conditions is not the comparison you asked for.")
    ap.add_argument("--tag", default=None,
                    help="cache namespace. A NEW tag re-measures everything "
                         "from scratch while staying resumable — use it when "
                         "comparing judges, so all conditions are measured at "
                         "the same time on the same model version.")
    args = ap.parse_args()

    if args.tag:
        judge_mod.set_tag(args.tag)

    state, cases = load()
    items = {i["id"]: i for i in state["items"]}
    order_all = [i["id"] for i in state["items"]]
    labels = state["labels"]

    w = sys.stdout.write
    w("\n" + "=" * 74 + "\n")
    w("JUDGE CALIBRATION\n")
    w("=" * 74 + "\n")

    # --- step 0a: is labels.json even current? ----------------------------
    # variants.py can change under a labels.json that was written before it.
    # Nothing else would notice: the file is well-formed, the items are
    # internally consistent, and the report would confidently describe a
    # dataset the generator no longer produces.
    fresh, _sk = variants.build_set(
        [c for c in json.load(open(DATASET, encoding="utf-8"))["cases"]],
        agent.run, limit=6)
    have = {(i["case_id"], i["kind"]) for i in items.values()}
    want = {(i["case_id"], i["kind"]) for i in fresh}
    if have != want:
        w(f"\n  ! STALE LABELS: labels.json has {len(have)} (case, kind) pairs, "
          f"the generator now produces {len(want)}.\n")
        for missing in sorted(want - have):
            w(f"      not yet labelled: {missing[0]} {missing[1]}\n")
        for extra in sorted(have - want):
            w(f"      no longer generated: {extra[0]} {extra[1]}\n")
        w("    Run `python3 -m evals.label` before trusting anything below.\n")

    # --- step 0b: is the reference itself sound? --------------------------
    broken_ids, broken = validate_reference(list(items.values()), cases)
    w("\nREFERENCE CHECK — validate the standard before blaming a rater\n")
    if broken:
        w(f"  {len(broken)} item(s) do not exhibit the defect their truth score\n"
          f"  claims. Scoring anyone against them measures nothing. EXCLUDED.\n")
        for b in broken:
            w(f"    {b['id']}  {b['case_id']:12} kind={b['kind']:9} "
              f"truth={b['truth']} human={labels.get(b['id'], '-')}\n")
            w(f"        -> {b['reason']}\n")
    else:
        w("  all degradations verified distinct from their original\n")

    order = [i for i in order_all if i in labels and i not in broken_ids]
    w(f"\n  usable items: {len(order)} of {len(items)}\n")

    human = [labels[i] for i in order]
    truth = [items[i]["truth"] for i in order]
    lengths = [len(items[i]["answer"]) for i in order]
    kinds = [items[i]["kind"] for i in order]

    # The retrieved documents for each case, so a context-aware judge can see
    # what the answer was supposed to be grounded in. The agent is
    # deterministic at TEMP=0, so re-running reproduces the original trace.
    traces = {}
    for lid in order:
        cid = items[lid]["case_id"]
        if cid not in traces:
            _text, tr = agent.run(cases[cid]["query"])
            traces[cid] = tr

    names = [n.strip() for n in args.judges.split(",") if n.strip()]
    unknown = [n for n in names if n not in judge_mod.JUDGES]
    if unknown:
        w(f"\nunknown judge(s): {unknown}. known: {list(judge_mod.JUDGES)}\n")
        return 2

    # --- preflight -------------------------------------------------------
    # Construct every judge first. A missing dependency or a bad key is worth
    # discovering in one second, not after a full pass over the dataset — and
    # certainly not as an aside in a report that otherwise looks complete.
    ready, failed = {}, []
    for name in names:
        try:
            ready[name] = judge_mod.JUDGES[name]()
        except Exception as exc:
            hint = ""
            if isinstance(exc, ModuleNotFoundError) and "openai" in str(exc):
                hint = "  -> pip install openai   (is your venv active?)"
            elif "api_key" in str(exc).lower():
                hint = "  -> export OPENAI_API_KEY=..."
            failed.append((name, f"{type(exc).__name__}: {exc}", hint))

    if failed:
        w("\n" + "!" * 74 + "\n")
        w(f"{len(failed)} of {len(names)} REQUESTED JUDGES COULD NOT RUN\n")
        for name, err, hint in failed:
            w(f"  {name:20} {err}\n")
            if hint:
                w(f"  {'':20} {hint}\n")
        w("!" * 74 + "\n")
        if not args.allow_partial:
            w("\nRefusing to print a comparison that did not happen. Every table\n"
              "below would be missing conditions you asked for, while looking\n"
              "complete — which is how a broken experiment gets quoted.\n"
              "Fix the above, or re-run with --allow-partial if you meant it.\n")
            return 2
        w("\n--allow-partial: continuing WITHOUT the judges above. Treat every\n"
          "table below as covering a subset of the requested comparison.\n")

    api_names = [n for n in ready if n.startswith("openai")]
    if api_names and not args.yes:
        calls = len(order) * len(api_names) * args.repeat
        w(f"\nThis will make ~{calls} API calls ({', '.join(api_names)}).\n")
        if input("proceed? [y/N] ").strip().lower() != "y":
            return 0

    results = {}
    for name, j in ready.items():
        try:
            scores, consistency = score_all(j, items, order, cases, traces,
                                            args.repeat, workers=args.workers)
        except judge_mod.JudgeUnavailable as exc:
            # Everything already fetched is on disk. Report the gap honestly
            # and keep going: a partial comparison beats no comparison, and
            # re-running tomorrow replays the cache for free.
            w(f"\n  {name}: INCOMPLETE — {exc}\n")
            continue
        results[name] = {"scores": scores, "consistency": consistency,
                         "temp_pinned": getattr(j, "supports_temperature", None)}

    w(f"\n  judge cache: {judge_mod.CACHE.stats()}   tag={judge_mod.tag()}\n")
    if judge_mod.CACHE.hits and judge_mod.CACHE.misses:
        w("    MIXED VINTAGE: part of this report is re-used from an earlier\n"
          "    run and part is fresh. Fine for iterating; for a comparison you\n"
          "    intend to quote, re-run with a new --tag so every judge is\n"
          "    measured under the same conditions.\n")

    if not results:
        w("\nno judges completed. Cached calls are kept — re-run when the\n"
          "quota resets and only the missing calls will be made.\n")
        return 1

    # --- agreement --------------------------------------------------------
    w(f"\nAGREEMENT vs GROUND TRUTH  (n={len(order)})\n")
    w(f"  {'rater':22} {'exact':>7} {'within 1':>9} {'kappa':>8} {'wtd kappa':>10}\n")
    w(f"  {'human':22} {agreement(human, truth):>6.0%} {agreement(human, truth, 1):>9.0%} "
      f"{kappa(human, truth):>8.2f} {kappa(human, truth, weighted=True):>10.2f}\n")
    for name, r in results.items():
        a = r["scores"]
        w(f"  {name:22} {agreement(a, truth):>6.0%} {agreement(a, truth, 1):>9.0%} "
          f"{kappa(a, truth):>8.2f} {kappa(a, truth, weighted=True):>10.2f}\n")

    w("\nAGREEMENT vs HUMAN LABELS\n")
    w(f"  {'judge':22} {'exact':>7} {'within 1':>9} {'kappa':>8} {'wtd kappa':>10}\n")
    for name, r in results.items():
        a = r["scores"]
        w(f"  {name:22} {agreement(a, human):>6.0%} {agreement(a, human, 1):>9.0%} "
          f"{kappa(a, human):>8.2f} {kappa(a, human, weighted=True):>10.2f}\n")

    # --- where the disagreement lives -------------------------------------
    w("\nMEAN SCORE BY VARIANT — the diagnostic table\n")
    header = f"  {'variant':10} {'n':>2} {'truth':>6} {'human':>6}"
    for name in results:
        header += f" {name[:14]:>15}"
    w(header + "\n")

    def mean_for(kind, series):
        sel = [i for i, kk in enumerate(kinds) if kk == kind]
        return (sum(series[i] for i in sel) / len(sel)) if sel else float("nan")

    for k in KINDS:
        sel = [i for i, kk in enumerate(kinds) if kk == k]
        if not sel:
            continue
        row = f"  {k:10} {len(sel):>2} {TRUTH[k]:>6} {mean_for(k, human):>6.2f}"
        for name, r in results.items():
            row += f" {mean_for(k, r['scores']):>15.2f}"
        w(row + "\n")

    w("\n  A judge that scores a degraded variant at or above its 'original'\n"
      "  row is blind to that defect, whatever its agreement number says.\n")
    if "heuristic" in results:
        w("\n  ! CIRCULARITY: 'omission' is DEFINED as removing a judge_keyword,\n"
          "    and HeuristicJudge scores on judge_keywords. It cannot miss this\n"
          "    defect — detection there is mechanical, not judgement. Discount\n"
          "    its omission column and any aggregate that includes it.\n")
    w(f"  'wrong' is the one that matters: truth={TRUTH['wrong']}, and detecting it\n"
      "  requires the retrieved documents — coherence alone cannot find it.\n")

    # --- bias probes -------------------------------------------------------
    w("\nBIAS PROBES\n")
    base_len_r = pearson(lengths, truth)
    w(f"  BASELINE  corr(length, TRUTH) = {base_len_r:+.2f}\n")
    w("    Read every length r below AGAINST this number, not against zero.\n"
      "    If the dataset's own defects correlate with length, a PERFECT rater\n"
      "    shows a length correlation too, and the probe measures the dataset\n"
      "    rather than the rater. |baseline| under ~0.15 means the probe is\n"
      "    interpretable; above that, fix the dataset before reading the column.\n\n")
    w(f"  {'rater':22} {'length r':>9} {'self-consistency':>18}\n")
    w(f"  {'human':22} {pearson(lengths, human):>+9.2f} {'n/a (single pass)':>18}\n")
    for name, r in results.items():
        c = r["consistency"]
        cs = f"{c:.0%}" if c is not None else "not measured"
        temp = r.get("temp_pinned")
        tag = "" if temp is None else ("  temp=0" if temp else "  temp=model default")
        w(f"  {name:22} {pearson(lengths, r['scores']):>+9.2f} {cs:>18}{tag}\n")
    w("    length r > 0 means longer answers score higher regardless of quality\n")
    w("    self-consistency = share of items where all --repeat runs agreed.\n"
      "    temperature=0 does NOT guarantee determinism, so this is measured.\n"
      "    'temp=model default' means the model REFUSED to be pinned (reasoning\n"
      "    models fix temperature at 1). Expect lower consistency there, and\n"
      "    treat a single-run score from such a judge as one draw, not a verdict.\n")

    seq = list(range(len(order)))
    w(f"\n  rater drift over time   r={pearson(seq, [human[i] - truth[i] for i in seq]):+.2f}\n")
    w("    correlation between labelling ORDER and (human - truth)\n")

    w("\nCAVEAT: one rater, n={}. There is no inter-rater agreement here, so\n"
      "'the judge agrees with a human' means it agrees with ONE human's taste,\n"
      "and a kappa from {} items has a wide confidence interval.\n".format(
          len(order), len(order)))
    w("=" * 74 + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
