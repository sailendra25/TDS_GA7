from datetime import UTC, datetime, timedelta

from fastapi import FastAPI, Request

app = FastAPI()

ASSIGNED_SUBJECT = "5abc1o.example"

VALID_TYPES = {
    "dns",
    "ct_log",
    "registry",
    "archive",
    "scan",
}


def response(verdict, confidence, sources):
    return {
        "verdict": verdict,
        "confidence": confidence,
        "corroboratingSources": sorted(sources),
    }


def parse_timestamp(value):
    if not isinstance(value, str):
        return None

    try:
        text = value

        # Support trailing Z.
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"

        dt = datetime.fromisoformat(text)

        # Treat naive timestamps as invalid rather than using wall clock.
        if dt.tzinfo is None:
            return None

        return dt.astimezone(UTC)

    except ValueError, TypeError:
        return None


def is_number(value):
    # bool is technically an int in Python, but must not count as a number.
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def valid_source(source):
    if not isinstance(source, dict):
        return False

    required = {
        "id",
        "type",
        "origin",
        "observedAt",
        "value",
        "authoritative",
    }

    if not required.issubset(source):
        return False

    if not isinstance(source["id"], str):
        return False

    if not isinstance(source["origin"], str):
        return False

    if not isinstance(source["value"], str):
        return False

    if not isinstance(source["observedAt"], str):
        return False

    if source["type"] not in VALID_TYPES:
        return False

    # authoritative is used as a boolean, so require boolean.
    if not isinstance(source["authoritative"], bool):
        return False

    return True


@app.post("/corroborate")
async def corroborate(request: Request):

    # ---------------------------------------------------------
    # Rule 1: INVALID
    # ---------------------------------------------------------
    try:
        body = await request.json()
    except Exception:
        return response("invalid", "low", [])

    if not isinstance(body, dict):
        return response("invalid", "low", [])

    if "claim" not in body:
        return response("invalid", "low", [])

    claim = body["claim"]

    if not isinstance(claim, dict):
        return response("invalid", "low", [])

    if "value" not in claim or not isinstance(claim["value"], str):
        return response("invalid", "low", [])

    if "asOf" not in body:
        return response("invalid", "low", [])

    as_of = parse_timestamp(body["asOf"])

    if as_of is None:
        return response("invalid", "low", [])

    if "stalenessDays" not in body:
        return response("invalid", "low", [])

    staleness_days = body["stalenessDays"]

    if not is_number(staleness_days):
        return response("invalid", "low", [])

    if "sources" not in body or not isinstance(body["sources"], list):
        return response("invalid", "low", [])

    claim_value = claim["value"]

    # ---------------------------------------------------------
    # Keep only valid sources.
    # Invalid sources are ignored entirely.
    # ---------------------------------------------------------
    valid_sources = []

    for source in body["sources"]:
        if not valid_source(source):
            continue

        observed = parse_timestamp(source["observedAt"])

        if observed is None:
            continue

        # Freshness:
        # asOf - observedAt <= stalenessDays
        age = as_of - observed

        if age <= timedelta(days=staleness_days):
            valid_sources.append(source)

    # ---------------------------------------------------------
    # Rule 2: CONTRADICTED
    # Fresh authoritative disagreement wins.
    # ---------------------------------------------------------
    contradicting = [
        source
        for source in valid_sources
        if source["authoritative"] is True and source["value"] != claim_value
    ]

    if contradicting:
        ids = sorted(source["id"] for source in contradicting)

        return response(
            "contradicted",
            "low",
            ids,
        )

    # ---------------------------------------------------------
    # Rule 3: SUPPORTED
    # Fresh matching sources only.
    # Reduce to one representative per origin.
    # Representative = lexicographically smallest ID.
    # ---------------------------------------------------------
    matching = [source for source in valid_sources if source["value"] == claim_value]

    representatives = {}

    for source in matching:
        origin = source["origin"]

        if (
            origin not in representatives
            or source["id"] < representatives[origin]["id"]
        ):
            representatives[origin] = source

    reps = list(representatives.values())

    if len(reps) >= 2:
        representative_ids = sorted(source["id"] for source in reps)

        distinct_types = {source["type"] for source in reps}

        if len(distinct_types) >= 2:
            confidence = "high"
        else:
            confidence = "medium"

        return response(
            "supported",
            confidence,
            representative_ids,
        )

    # ---------------------------------------------------------
    # Rule 4: UNVERIFIED
    # ---------------------------------------------------------
    return response(
        "unverified",
        "low",
        [],
    )


@app.get("/")
def root():
    return {"status": "ok"}
