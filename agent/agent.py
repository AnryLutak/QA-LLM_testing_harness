"""The agent under test.

A four-stage pipeline, the same shape as most production RAG/agent systems:

    route  ->  retrieve  ->  tool_call  ->  generate

Every stage appends to a trace. That trace is the whole reason the harness can
say *where* something broke instead of only *that* it broke, which is the
difference between a failing test and an actionable one.

Bugs can be switched on with the BUGS environment variable, e.g.

    BUGS=retrieval_ignores_city python3 -m evals.runner

so the harness can be shown catching regressions rather than just asserting
that it would. Every seeded bug is modelled on something that actually happens:
a router that over-triggers, a retriever that drops a filter, a tool that
rounds the wrong way, a generator that states a number nobody retrieved.
"""

import os
import re

from agent import knowledge, noise

BUGS = {b.strip() for b in os.environ.get("BUGS", "").split(",") if b.strip()}

# Promoted to module level so noise.py can ask "was this query ambiguous?"
# without duplicating the word lists.
POLICY_WORDS = ("deposit", "pet", "cancel", "policy", "allowed", "refund")
SEARCH_WORDS = ("flat", "apartment", "house", "bedroom", "bed", "rent",
                "looking for", "find", "studio", "home", "place", "places",
                "property", "properties", "cheapest", "available", "show me")


class Trace:
    """Ordered record of what each stage did. Stages append; nothing rewrites."""

    STAGES = ["routing", "retrieval", "tool_call", "generation"]

    def __init__(self):
        self.steps = []

    def add(self, stage, **data):
        assert stage in self.STAGES, f"unknown stage {stage}"
        self.steps.append({"stage": stage, **data})

    def get(self, stage):
        for s in self.steps:
            if s["stage"] == stage:
                return s
        return None

    def as_dict(self):
        return {"steps": self.steps}


# --------------------------------------------------------------------------
# Stage 1 — routing
# --------------------------------------------------------------------------

def route(query, trace, rng=None):
    """Classify intent. Keyword rules stand in for a model call.

    Order matters: 'policy' is checked first because a question like
    "can I have a pet in a 2-bed in Seville?" is a policy question that merely
    mentions a search. Routers that check search first get this wrong, which is
    exactly the `router_prefers_search` bug below.
    """
    q = query.lower()
    policy_hit = any(w in q for w in POLICY_WORDS)
    search_hit = any(w in q for w in SEARCH_WORDS)

    if "router_prefers_search" in BUGS:
        intent = "search" if search_hit else "policy" if policy_hit else "chitchat"
    else:
        intent = "policy" if policy_hit else "search" if search_hit else "chitchat"

    # A query matching BOTH word sets sits on the classifier's decision
    # boundary — those are the ones a real router flips on between runs.
    settled = intent
    intent = noise.maybe_misroute(intent, policy_hit and search_hit, rng)

    trace.add("routing", intent=intent, query=query,
              flipped=intent != settled)
    return intent


# --------------------------------------------------------------------------
# Stage 2 — retrieval
# --------------------------------------------------------------------------

def _parse_filters(query):
    q = query.lower()
    filters = {}

    known_cities = ("seville", "madrid", "barcelona", "valencia")
    for city in known_cities:
        if city in q:
            filters["city"] = city.capitalize()
            break
    else:
        # A location we do not cover still has to be applied as a filter, so it
        # correctly returns nothing. Dropping it made "a house in Bilbao"
        # return all eight listings across four other cities.
        m = re.search(r"\bin ([a-z]{3,})\b", q)
        if m and m.group(1) not in ("the", "any", "all"):
            filters["city"] = m.group(1).capitalize()

    beds = re.search(r"(\d+)\s*(?:-|\s)?\s*bed", q)
    if beds:
        filters["beds"] = int(beds.group(1))
    elif "studio" in q:
        filters["beds"] = 1

    budget = re.search(r"under\s*(\d+)|below\s*(\d+)|max\s*(\d+)", q)
    if budget:
        filters["max_price"] = int(next(g for g in budget.groups() if g))

    if "furnished" in q and "unfurnished" not in q:
        filters["furnished"] = True
    elif "unfurnished" in q:
        filters["furnished"] = False

    return filters


def retrieve(query, intent, trace, rng=None):
    filters = _parse_filters(query)

    if "retrieval_ignores_city" in BUGS:
        filters.pop("city", None)

    if intent == "policy":
        q = query.lower()
        topic = ("deposit" if "deposit" in q
                 else "pets" if "pet" in q
                 else "cancellation" if "cancel" in q else None)
        # No recognised topic means no matching document. Returning all of them
        # produces a confidently wrong answer assembled from unrelated policies.
        docs = [d for d in knowledge.POLICIES if d["topic"] == topic] if topic else []
    elif intent == "search":
        docs = knowledge.LISTINGS
        if "city" in filters:
            docs = [d for d in docs if d["city"] == filters["city"]]
        if "beds" in filters:
            docs = [d for d in docs if d["beds"] == filters["beds"]]
        if "max_price" in filters:
            docs = [d for d in docs if d["price"] <= filters["max_price"]]
        if "furnished" in filters:
            docs = [d for d in docs if d["furnished"] == filters["furnished"]]
    else:
        docs = []

    if "retrieval_returns_everything" in BUGS and intent == "search":
        docs = knowledge.LISTINGS

    # Threshold jitter: a marginal document in on one run, out on the next.
    pool = knowledge.LISTINGS if intent == "search" else knowledge.POLICIES
    docs = noise.perturb_retrieval(docs, pool, rng)

    doc_ids = [d["id"] for d in docs]
    trace.add("retrieval", filters=filters, doc_ids=doc_ids, count=len(doc_ids))
    return docs


# --------------------------------------------------------------------------
# Stage 3 — tools
# --------------------------------------------------------------------------

def call_tools(query, intent, docs, trace):
    """Only the calls a real system would make. Cheapest stage to assert on."""
    calls = []

    if intent == "search" and docs:
        prices = [d["price"] for d in docs]
        avg = sum(prices) / len(prices)
        if "tool_rounds_wrong" in BUGS:
            avg = int(avg)            # truncation dressed up as rounding
        else:
            avg = round(avg)
        calls.append({"name": "average_price", "args": {"n": len(docs)}, "result": avg})

    # Booking requires BOTH a booking word and search intent. Keying on the word
    # alone made "Can I cancel a viewing?" book one, which is the classic
    # keyword-trigger bug: the word is present, the intent is the opposite.
    #
    # It also requires a non-empty result set. Without that guard, "book a
    # viewing for a 5 bedroom flat" matched nothing and still booked a viewing
    # with listing_id=None — the answer read "I couldn't find any properties
    # ... I've started a viewing request for you."
    wants_booking = any(w in query.lower() for w in ("book", "viewing", "schedule", "arrange"))
    if intent == "search" and wants_booking and docs:
        if "tool_skips_booking" not in BUGS:
            calls.append({"name": "book_viewing",
                          "args": {"listing_id": docs[0]["id"]},
                          "result": "pending_confirmation"})

    trace.add("tool_call", calls=calls, names=[c["name"] for c in calls])
    return calls


# --------------------------------------------------------------------------
# Stage 4 — generation
# --------------------------------------------------------------------------

def generate(query, intent, docs, calls, trace, rng=None):
    """Compose the answer strictly from retrieved documents.

    The `generation_hallucinates_price` bug invents a number that appears in no
    retrieved document — the single most common and most damaging failure in a
    RAG system, and the one a pass/fail assertion on the final string alone
    tends to miss.
    """
    if intent == "chitchat":
        text = "I can help you find a property or answer questions about our rental policies."

    elif intent == "policy":
        if not docs:
            text = "I don't have a policy document covering that."
        else:
            text = " ".join(d["text"] for d in docs)

    else:
        if not docs:
            text = "I couldn't find any properties matching those criteria."
        else:
            lines = [f"{d['text']}" for d in docs[:3]]
            avg = next((c["result"] for c in calls if c["name"] == "average_price"), None)
            text = f"I found {len(docs)} matching properties. " + " ".join(lines)
            if avg is not None:
                text += f" The average price is {avg} EUR/month."
            if "generation_hallucinates_price" in BUGS:
                text += " Some listings start from 400 EUR/month."

    if any(c["name"] == "book_viewing" for c in calls):
        text += " I've started a viewing request for you."

    # Surface variation. Changes no facts — only how they are written.
    canonical = text
    text = noise.maybe_drop_average(text, rng)
    text = noise.paraphrase(text, rng)

    trace.add("generation", text=text, grounded_in=[d["id"] for d in docs],
              reworded=text != canonical)
    return text


# --------------------------------------------------------------------------

def run(query, rng=None):
    """Answer one query. Returns (text, trace).

    rng=None means fully deterministic — identical bytes every call, which is
    what the original suite relied on. Pass a Random (and set TEMP>0) to get a
    system that behaves like an LLM instead of like a lookup table.
    """
    trace = Trace()
    intent = route(query, trace, rng)
    docs = retrieve(query, intent, trace, rng)
    calls = call_tools(query, intent, docs, trace)
    text = generate(query, intent, docs, calls, trace, rng)
    return text, trace
