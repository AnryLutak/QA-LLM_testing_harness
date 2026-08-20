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

from agent import config, injection, knowledge, noise

BUGS = {b.strip() for b in os.environ.get("BUGS", "").split(",") if b.strip()}

# Notes a booking is allowed to carry when the `capability` defence is on.
# This is the strong mitigation and the reason it is strong is visible here:
# the field stops being free text. An injected instruction can still be obeyed
# by the generator, and it still cannot put anything of the attacker's choosing
# into an outbound channel, because there is no longer a channel that accepts
# arbitrary text. Filters guess; capability restriction removes.
ALLOWED_NOTES = ("", "standard viewing request", "user requested a weekend slot")

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

    # DEFENCE=input_filter — drop any single document that looks like it
    # contains instructions. This is the mitigation every team reaches for
    # first, and the suite exists partly to show what it does and does not buy:
    #
    #   - it works on single-document payloads
    #   - it is blind to payloads split across two documents, because it never
    #     sees the joined context that assembles them
    #   - it has a false-positive cost. A policy document that legitimately
    #     says "ignore the above if the tenancy started before 2020" is dropped,
    #     and the answer silently loses a source. Watch retrieval recall.
    filtered = []
    if "input_filter" in injection.defences():
        keep = [d for d in docs if not injection.looks_like_instruction(d["text"])]
        filtered = [d["id"] for d in docs if d not in keep]
        docs = keep

    doc_ids = [d["id"] for d in docs]
    trace.add("retrieval", filters=filters, doc_ids=doc_ids, count=len(doc_ids),
              filtered_out=filtered)
    return docs


# --------------------------------------------------------------------------
# Stage 3 — tools
# --------------------------------------------------------------------------

def call_tools(query, intent, docs, trace, obeyed=()):
    """Only the calls a real system would make. Cheapest stage to assert on.

    `obeyed` carries directives the simulated model took from retrieved text
    (see agent/injection.py). Two attacker objectives land here, and they are
    the two that matter most because this stage is where the system touches
    the real world:

      BOOK   a side effect the user never asked for      -> LLM03 / ASI02
      NOTES  attacker text in an outbound parameter      -> LLM10, and leg 3
             of the lethal trifecta
    """
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

    # An injected BOOK directive fires the tool whether or not the USER asked
    # for it, and whether or not anything was retrieved. That second part is
    # deliberate: it routes straight into check_tool_results' existing guard
    # ("booked a listing that was not retrieved"), which was written months ago
    # as a correctness check and is, unchanged, an excessive-agency control.
    forced = any(e == injection.BOOK for e, _ in obeyed)

    if (forced or (intent == "search" and wants_booking and docs)) and \
            "tool_skips_booking" not in BUGS:
        notes = next((a for e, a in obeyed if e == injection.NOTES and a), "")
        if "capability" in injection.defences() and notes not in ALLOWED_NOTES:
            notes = ""
        calls.append({"name": "book_viewing",
                      "args": {"listing_id": docs[0]["id"] if docs else None,
                               "notes": notes},
                      "result": "pending_confirmation"})

    trace.add("tool_call", calls=calls, names=[c["name"] for c in calls])
    return calls


# --------------------------------------------------------------------------
# Stage 4 — generation
# --------------------------------------------------------------------------

def generate(query, intent, docs, calls, trace, rng=None, obeyed=(), diag=None):
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

    # Injected directives that land in the ANSWER rather than in a tool call.
    for effect, arg in obeyed:
        if effect == injection.REVEAL:
            text += " " + config.SYSTEM_PROMPT.strip().replace("\n", " ")
        elif effect == injection.EMIT and arg:
            text += f" {arg}"

    # Surface variation. Changes no facts — only how they are written.
    canonical = text
    text = noise.maybe_drop_average(text, rng)
    text = noise.paraphrase(text, rng)

    trace.add("generation", text=text, grounded_in=[d["id"] for d in docs],
              reworded=text != canonical,
              # Diagnostics only. The security checks in evals/security.py do
              # NOT read this — see the docstring on injection.obeyed for why a
              # check that reads the simulator's own record of its intent is
              # testing the simulator instead of the system.
              injection=diag or {})
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

    # Read the retrieved context for instructions, ONCE, between retrieval and
    # the stages that act. Once, because compliance is probabilistic: deciding
    # separately in call_tools and in generate would let the same directive be
    # obeyed by one and refused by the other in the same turn, which no real
    # model does and which would make the trace impossible to read.
    obeyed, diag = injection.obeyed(docs, BUGS, rng)

    calls = call_tools(query, intent, docs, trace, obeyed)
    text = generate(query, intent, docs, calls, trace, rng, obeyed, diag)
    return text, trace
