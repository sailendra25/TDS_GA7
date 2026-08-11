import re
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()

SHA40 = re.compile(r"^[0-9a-f]{40}$")


class ReleaseGate(BaseModel):
    target: str
    event: str
    ref: str
    workflow: dict[str, Any]
    image: dict[str, Any]


@app.post("/release-gate")
def release_gate(req: ReleaseGate):
    violations = []

    w = req.workflow
    img = req.image

    # 1. Permissions must be exactly least privilege.
    expected_permissions = {
        "contents": "read",
        "packages": "write",
        "id-token": "none",
    }

    if w.get("permissions") != expected_permissions:
        violations.append("EXCESS_PERMISSION")

    # 2. Pull requests must use pull_request, never pull_request_target.
    if req.event == "pull_request" and w.get("trigger") != "pull_request":
        violations.append("UNSAFE_PR_TRIGGER")

    # 3. Tests/matrix/failFast requirements.
    if (
        w.get("testsPassed") is not True
        or w.get("matrixComplete") is not True
        or w.get("failFast") is not False
    ):
        violations.append("TESTS_INCOMPLETE")

    # 4. Action pinning.
    for action in w.get("actions", []):
        owner = action.get("owner")
        ref = action.get("ref", "")

        if owner != "actions" and not SHA40.fullmatch(ref):
            violations.append("MUTABLE_ACTION")
            break

    # 5. Hardened image requirements.
    if img.get("multiStage") is not True:
        violations.append("SINGLE_STAGE_IMAGE")

    if img.get("runsAsRoot") is not False:
        violations.append("ROOT_RUNTIME")

    if img.get("secretMode") not in ("none", "buildkit"):
        violations.append("SECRET_IN_LAYER")

    if img.get("criticalVulnerabilities") != 0:
        violations.append("CRITICAL_CVE")

    if img.get("digestPinned") is not True:
        violations.append("UNPINNED_IMAGE")

    # 6. Production requirements.
    if req.target == "production":
        if req.event != "push" or req.ref != "refs/heads/main":
            violations.append("INVALID_PRODUCTION_REF")

        if w.get("environmentApproval") is not True:
            violations.append("APPROVAL_REQUIRED")

    return {
        "decision": "promote" if not violations else "block",
        "violations": violations,
    }
