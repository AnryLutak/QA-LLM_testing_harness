"""Tiny in-memory knowledge base for the agent under test.

Deliberately small and boring. The point of this repo is the evaluation
harness, not the agent — but the agent has to be real enough that its
failures look like the failures of a real RAG pipeline.
"""

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

DOCS = LISTINGS + POLICIES


def get(doc_id):
    for d in DOCS:
        if d["id"] == doc_id:
            return d
    return None
