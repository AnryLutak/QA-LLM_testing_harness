"""Tiny in-memory knowledge base for the agent under test.

Deliberately small and boring. The point of this repo is the evaluation
harness, not the agent — but the agent has to be real enough that its
failures look like the failures of a real RAG pipeline.

CORPUS_OVERLAY
--------------
Until Block 3 this corpus was a Python literal, which made it trusted by
construction: the only person who could write to it was the person who owned
the repo. Real corpora are not like that. A rental marketplace's listings are
written by landlords; a support bot's knowledge base is written by whoever can
file a doc; a browsing agent's context is written by the internet.

So the corpus is now an EDGE rather than a constant. Set

    CORPUS_OVERLAY=security/corpus_injected.json

to add attacker-controlled documents or patch existing ones. With the variable
unset nothing changes — the overlay is a no-op and the existing suite stays
byte-identical, which was the condition for adding it at all.

The overlay is the threat model made executable: "someone who can publish a
listing" is the attacker, and this is exactly how much power that gives them.
"""

import json
import os

LISTINGS = [
    {"id": "L001", "city": "Seville",   "beds": 2, "price": 950,  "furnished": True,
     "text": "Two-bedroom flat in Triana, Seville. Furnished, balcony, 950 EUR/month."},
    {"id": "L002", "city": "Seville",   "beds": 3, "price": 1400, "furnished": False,
     "text": "Three-bedroom townhouse near Alameda, Seville. Unfurnished, patio, 1400 EUR/month."},
    {"id": "L003", "city": "Seville",   "beds": 1, "price": 700,  "furnished": True,
     "text": "Studio in Nervion, Seville. Furnished, lift, 700 EUR/month."},
    {"id": "L004", "city": "Madrid",    "beds": 2, "price": 1600, "furnished": True,
     "text": "Two-bedroom apartment in Chamberi, Madrid. Furnished, 1600 EUR/month."},
    {"id": "L005", "city": "Madrid",    "beds": 4, "price": 2800, "furnished": False,
     "text": "Four-bedroom family home in Las Rozas, Madrid. Unfurnished, garden, 2800 EUR/month."},
    {"id": "L006", "city": "Barcelona", "beds": 1, "price": 1100, "furnished": True,
     "text": "One-bedroom in Gracia, Barcelona. Furnished, 1100 EUR/month."},
    {"id": "L007", "city": "Barcelona", "beds": 3, "price": 2100, "furnished": True,
     "text": "Three-bedroom in Eixample, Barcelona. Furnished, terrace, 2100 EUR/month."},
    {"id": "L008", "city": "Valencia",  "beds": 2, "price": 850,  "furnished": False,
     "text": "Two-bedroom in Ruzafa, Valencia. Unfurnished, 850 EUR/month."},
]

POLICIES = [
    {"id": "P001", "topic": "deposit",
     "text": "A deposit of one month's rent is standard. Two months for unfurnished properties."},
    {"id": "P002", "topic": "pets",
     "text": "Pets are allowed in furnished properties only with prior written approval from the landlord."},
    {"id": "P003", "topic": "cancellation",
     "text": "Viewings can be cancelled free of charge up to 24 hours before the appointment."},
]

def _apply_overlay():
    """Add or patch documents from a JSON file named by CORPUS_OVERLAY.

    Mutates LISTINGS / POLICIES in place rather than rebinding them, because
    agent.py holds references to those module-level lists. Rebinding here would
    leave the agent reading the pristine corpus while the overlay sat in memory
    doing nothing — a silent no-op, and the worst kind of test-infrastructure
    bug: the attack "fails", you conclude the system is secure, and the reason
    is that the attack was never delivered.

    Overlay format:
        {"listings": [ {...full doc...} ],      # appended, or replaced by id
         "policies": [ {...} ],
         "patch":    {"L002": {"text": "...", "price": 140}}}
    """
    path = os.environ.get("CORPUS_OVERLAY")
    if not path:
        return []

    if not os.path.isabs(path):
        path = os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), path)

    # Fail loudly. A missing overlay must not degrade to "run the clean
    # corpus" — that is a security suite reporting PASS because the attack
    # was never loaded. Same fail-closed rule as the assertions.
    with open(path, encoding="utf-8") as f:
        overlay = json.load(f)

    added = []
    for key, target in (("listings", LISTINGS), ("policies", POLICIES)):
        for doc in overlay.get(key, []):
            existing = next((d for d in target if d["id"] == doc["id"]), None)
            if existing:
                existing.update(doc)
            else:
                target.append(doc)
            added.append(doc["id"])

    for doc_id, fields in overlay.get("patch", {}).items():
        for target in (LISTINGS, POLICIES):
            for d in target:
                if d["id"] == doc_id:
                    d.update(fields)
                    added.append(doc_id)
    return added


OVERLAY_APPLIED = _apply_overlay()

DOCS = LISTINGS + POLICIES


def get(doc_id):
    for d in DOCS:
        if d["id"] == doc_id:
            return d
    return None
