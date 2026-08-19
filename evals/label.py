"""Blind labelling CLI. You score answers; the harness hides what they are.

    python3 -m evals.label                 # label everything unlabelled
    python3 -m evals.label --reset         # start over
    python3 -m evals.label --status        # how far through am I

Two design choices worth understanding, because they are what make the
resulting numbers mean anything:

BLIND. The variant kind and its ground-truth score are never shown while you
are scoring. If you knew an answer was the "wrong" variant you would score it
1 without reading, and your labels would measure your memory rather than your
judgement. This is the same reason a human rater in a real eval never sees
which model produced which answer.

SHUFFLED, WITH A FIXED SEED. Variants of the same query are scattered so you
do not score five near-identical answers in a row and anchor on the first.
The seed is fixed so the order is reproducible — you can stop, restart, and
still be labelling the same experiment.

One thing NOT handled here, deliberately: you are a single rater, so there is
no inter-rater agreement to compute. That is a real limitation and the
calibration report should say so out loud. A judge that agrees with one
person is calibrated to one person.
"""

import argparse
import json
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent import agent                       # noqa: E402
from evals import rubric, variants             # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
DATASET = os.path.join(HERE, "dataset.json")
LABELS = os.path.join(HERE, "labels.json")

SEED = "calibration-v1"

# Imported, not duplicated. The judge is sent the identical text — see
# evals/rubric.py for why that is not optional.
RUBRIC = rubric.block()


def build_items():
    with open(DATASET, encoding="utf-8") as f:
        cases = json.load(f)["cases"]
    items, skipped = variants.build_set(cases, agent.run, limit=6)
    random.Random(SEED).shuffle(items)
    for i, it in enumerate(items):
        it["id"] = f"lbl-{i:03d}"
    return items, skipped


def load():
    """Regenerate the item set, carrying forward labels that still apply.

    The item set is ALWAYS rebuilt from the current variants.py, because a
    stale labels.json would silently keep scoring answers the generator no
    longer produces. But relabelling everything whenever one degradation is
    fixed is a good way to make nobody ever fix one.

    So labels migrate by CONTENT, not by id. An item is the same item if its
    (case_id, kind, answer) is unchanged; ids are positional and shift as soon
    as the set changes size. Anything whose answer changed loses its label and
    comes back round for relabelling — which is correct: it is a different
    answer, and the old score was for a different string.
    """
    items, skipped = build_items()
    labels, dropped = {}, 0

    if os.path.exists(LABELS):
        with open(LABELS, encoding="utf-8") as f:
            old = json.load(f)
        by_content = {}
        for it in old.get("items", []):
            if it["id"] in old.get("labels", {}):
                by_content[(it["case_id"], it["kind"], it["answer"])] = \
                    old["labels"][it["id"]]
        for it in items:
            key = (it["case_id"], it["kind"], it["answer"])
            if key in by_content:
                labels[it["id"]] = by_content[key]
        dropped = len(by_content) - len(labels)

    return {"items": items, "labels": labels, "skipped": skipped,
            "_migrated": dropped}


def save(state):
    with open(LABELS, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--reset", action="store_true")
    ap.add_argument("--status", action="store_true")
    args = ap.parse_args()

    if args.reset and os.path.exists(LABELS):
        os.remove(LABELS)

    state = load()
    items, labels = state["items"], state["labels"]
    todo = [it for it in items if it["id"] not in labels]

    if state.get("_migrated"):
        print(f"NOTE: {state['_migrated']} old label(s) dropped — those answers "
              f"changed, so the old scores were for different text.")
    for sk in state.get("skipped", []):
        print(f"NOTE: no {sk['kind']} variant for {sk['case_id']} — {sk['reason']}")

    if args.status:
        print(f"{len(labels)}/{len(items)} labelled, {len(todo)} remaining")
        return 0

    print(RUBRIC)
    print(f"{len(todo)} to go. Enter 1-5, 's' to skip, 'q' to save and quit.\n")

    for it in todo:
        print("=" * 70)
        print(f"Q: {it['query']}")
        print(f"A: {it['answer']}")
        # NOTE: it['kind'] and it['truth'] exist on this object and are
        # deliberately not printed. Blind is the whole point.
        while True:
            raw = input("score 1-5 > ").strip().lower()
            if raw == "q":
                save(state)
                print(f"\nsaved. {len(labels)}/{len(items)} labelled.")
                return 0
            if raw == "s":
                break
            if raw in {"1", "2", "3", "4", "5"}:
                labels[it["id"]] = int(raw)
                save(state)          # save every answer; never lose work
                break
            print("  1-5, or s / q")

    save(state)
    print(f"\ndone. {len(labels)}/{len(items)} labelled -> {LABELS}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
