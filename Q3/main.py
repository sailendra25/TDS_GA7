from fastapi import FastAPI, Request

app = FastAPI()

ASSIGNED_ENVIRONMENT = "prod-65oik1"

REQUIRED_LABELS = {
    "owner": "student-j2x9p",
    "environment": "production",
    "cost_center": "cc-cm3f",
}

ALLOWED_BACKENDS = {"gcs", "s3", "azurerm", "remote"}
ALLOWED_ACTIONS = {"create", "update", "delete"}
DESTRUCTIVE_TYPES = {"storage_bucket", "sql_database", "persistent_disk"}

VALID_PROVIDER_VERSIONS = {
    "6.2.1",
    "= 6.2.1",
    "~> 6.0",
}


def result(decision: str, reason: str):
    return {
        "decision": decision,
        "reason": reason,
    }


def is_bool(value):
    # bool is a subclass of int in Python, so check explicitly.
    return isinstance(value, bool)


def valid_string(value):
    return isinstance(value, str)


@app.post("/terraform/plan")
async def terraform_plan(request: Request):
    # ---------------------------------------------------------
    # Rule 1: Validate request and nested object value types
    # ---------------------------------------------------------
    try:
        data = await request.json()
    except Exception:
        return result("reject", "INVALID_PLAN")

    if not isinstance(data, dict):
        return result("reject", "INVALID_PLAN")

    # Required top-level fields
    required_top = {
        "environment",
        "state",
        "providerVersion",
        "destroyApproved",
        "resource",
    }

    if not required_top.issubset(data.keys()):
        return result("reject", "INVALID_PLAN")

    if not valid_string(data["environment"]):
        return result("reject", "INVALID_PLAN")

    if not isinstance(data["state"], dict):
        return result("reject", "INVALID_PLAN")

    if not valid_string(data["providerVersion"]):
        return result("reject", "INVALID_PLAN")

    if not is_bool(data["destroyApproved"]):
        return result("reject", "INVALID_PLAN")

    if not isinstance(data["resource"], dict):
        return result("reject", "INVALID_PLAN")

    state = data["state"]
    resource = data["resource"]

    # State fields
    if "backend" not in state or "locked" not in state:
        return result("reject", "INVALID_PLAN")

    if not valid_string(state["backend"]):
        return result("reject", "INVALID_PLAN")

    if not is_bool(state["locked"]):
        return result("reject", "INVALID_PLAN")

    # Resource fields
    required_resource = {
        "address",
        "type",
        "action",
        "labels",
        "secret",
        "forceDestroy",
    }

    if not required_resource.issubset(resource.keys()):
        return result("reject", "INVALID_PLAN")

    if not valid_string(resource["address"]):
        return result("reject", "INVALID_PLAN")

    if not valid_string(resource["type"]):
        return result("reject", "INVALID_PLAN")

    if not valid_string(resource["action"]):
        return result("reject", "INVALID_PLAN")

    if resource["action"] not in ALLOWED_ACTIONS:
        return result("reject", "INVALID_PLAN")

    if not isinstance(resource["labels"], dict):
        return result("reject", "INVALID_PLAN")

    if not all(
        isinstance(k, str) and isinstance(v, str) for k, v in resource["labels"].items()
    ):
        return result("reject", "INVALID_PLAN")

    if resource["secret"] is not None and not valid_string(resource["secret"]):
        return result("reject", "INVALID_PLAN")

    if not is_bool(resource["forceDestroy"]):
        return result("reject", "INVALID_PLAN")

    # ---------------------------------------------------------
    # Rule 2: Environment must exactly match assigned workspace
    # ---------------------------------------------------------
    if data["environment"] != ASSIGNED_ENVIRONMENT:
        return result("reject", "ENVIRONMENT_MISMATCH")

    # ---------------------------------------------------------
    # Rule 3: Safe and locked remote state
    # ---------------------------------------------------------
    if state["backend"] not in ALLOWED_BACKENDS:
        return result("reject", "STATE_UNSAFE")

    if state["locked"] is not True:
        return result("reject", "STATE_UNSAFE")

    # ---------------------------------------------------------
    # Rule 4: Provider must be pinned
    # ---------------------------------------------------------
    if data["providerVersion"] not in VALID_PROVIDER_VERSIONS:
        return result("reject", "UNPINNED_PROVIDER")

    # ---------------------------------------------------------
    # Rule 5: Required cost-ownership labels
    # ---------------------------------------------------------
    labels = resource["labels"]

    for key, expected_value in REQUIRED_LABELS.items():
        if key not in labels or labels[key] != expected_value:
            return result("reject", "MISSING_LABELS")

    # ---------------------------------------------------------
    # Rule 6: Secret must be null or secret:// reference
    # ---------------------------------------------------------
    secret = resource["secret"]

    if secret is not None:
        if not secret.startswith("secret://"):
            return result("reject", "PLAINTEXT_SECRET")

        # Must contain something after secret://
        if len(secret) <= len("secret://"):
            return result("reject", "PLAINTEXT_SECRET")

    # ---------------------------------------------------------
    # Rule 7: Destructive deletes require approval
    # ---------------------------------------------------------
    if (
        resource["action"] == "delete"
        and resource["type"] in DESTRUCTIVE_TYPES
        and data["destroyApproved"] is not True
    ):
        return result("reject", "DELETE_NOT_APPROVED")

    # ---------------------------------------------------------
    # Rule 8: Production storage bucket cannot force destroy
    # ---------------------------------------------------------
    if (
        data["environment"] == ASSIGNED_ENVIRONMENT
        and resource["type"] == "storage_bucket"
        and resource["forceDestroy"] is True
    ):
        return result("reject", "FORCE_DESTROY")

    # ---------------------------------------------------------
    # Everything passed
    # ---------------------------------------------------------
    return result("approve", "APPROVE")


@app.get("/")
def root():
    return {"status": "ok"}
