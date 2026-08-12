import re
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()

ASSIGNED_TENANT = "tenant-9adbghs"
ALLOWED_EMAIL_DOMAIN = "notify-jnsz6kg.example"

ALLOWED_TOOLS = {
    "search",
    "lookup_record",
    "send_email",
    "render_html",
}


class ActionRequest(BaseModel):
    provenance: str
    humanApproved: bool
    untrustedContent: str | None = None
    action: dict[str, Any]


def block(reason: str):
    return {
        "decision": "block",
        "reason": reason,
    }


def allow():
    return {
        "decision": "allow",
        "reason": "ALLOW",
    }


def is_unsafe_html(html: str) -> bool:
    # Block <script> tags
    if re.search(r"<\s*script\b", html, re.IGNORECASE):
        return True

    # Block <iframe> tags
    if re.search(r"<\s*iframe\b", html, re.IGNORECASE):
        return True

    # Block inline event handlers such as onclick=, onload=, onerror=
    if re.search(r"\bon[a-z]+\s*=", html, re.IGNORECASE):
        return True

    # Block javascript: URLs
    if re.search(r"javascript\s*:", html, re.IGNORECASE):
        return True

    return False


@app.post("/action-firewall")
def action_firewall(request: ActionRequest):

    # =========================================================
    # 1. TOP-LEVEL SCHEMA
    # =========================================================

    if request.provenance not in {"trusted", "untrusted"}:
        return block("INVALID_SCHEMA")

    if not isinstance(request.humanApproved, bool):
        return block("INVALID_SCHEMA")

    if request.untrustedContent is not None:
        if not isinstance(request.untrustedContent, str):
            return block("INVALID_SCHEMA")

    if not isinstance(request.action, dict):
        return block("INVALID_SCHEMA")

    if set(request.action.keys()) != {"tool", "args"}:
        return block("INVALID_SCHEMA")

    tool = request.action["tool"]
    args = request.action["args"]

    if not isinstance(tool, str):
        return block("INVALID_SCHEMA")

    if not isinstance(args, dict):
        return block("INVALID_SCHEMA")

    # =========================================================
    # 2. TOOL ALLOWLIST
    # =========================================================

    if tool not in ALLOWED_TOOLS:
        return block("TOOL_NOT_ALLOWED")

    # =========================================================
    # 3. TOOL ARGUMENT SCHEMA
    # =========================================================

    if tool == "search":
        if set(args.keys()) != {"query"}:
            return block("INVALID_SCHEMA")

        query = args["query"]

        if not isinstance(query, str):
            return block("INVALID_SCHEMA")

        if not (1 <= len(query) <= 200):
            return block("INVALID_SCHEMA")

    elif tool == "lookup_record":
        if set(args.keys()) != {"tenantId", "recordId"}:
            return block("INVALID_SCHEMA")

        if not isinstance(args["tenantId"], str):
            return block("INVALID_SCHEMA")

        if not isinstance(args["recordId"], str):
            return block("INVALID_SCHEMA")

        if args["recordId"] == "":
            return block("INVALID_SCHEMA")

    elif tool == "send_email":
        if set(args.keys()) != {"to", "subject", "body"}:
            return block("INVALID_SCHEMA")

        if not isinstance(args["to"], str):
            return block("INVALID_SCHEMA")

        if not isinstance(args["subject"], str):
            return block("INVALID_SCHEMA")

        if not isinstance(args["body"], str):
            return block("INVALID_SCHEMA")

    elif tool == "render_html":
        if set(args.keys()) != {"html"}:
            return block("INVALID_SCHEMA")

        if not isinstance(args["html"], str):
            return block("INVALID_SCHEMA")

    # =========================================================
    # 4. TENANT SCOPE
    # =========================================================

    if tool == "lookup_record":
        if args["tenantId"] != ASSIGNED_TENANT:
            return block("TENANT_SCOPE")

    # =========================================================
    # 5. EXACT EMAIL DOMAIN
    # =========================================================

    if tool == "send_email":
        recipient = args["to"]

        # Require a single basic email address.
        if not re.fullmatch(r"[^@\s]+@[^@\s]+", recipient):
            return block("EGRESS_DENIED")

        domain = recipient.rsplit("@", 1)[1]

        # Exact domain match.
        if domain != ALLOWED_EMAIL_DOMAIN:
            return block("EGRESS_DENIED")

    # =========================================================
    # 6. HUMAN APPROVAL
    # =========================================================

    if tool == "send_email":
        if request.humanApproved is not True:
            return block("APPROVAL_REQUIRED")

    # =========================================================
    # 7. HTML SAFETY
    # =========================================================

    if tool == "render_html":
        if is_unsafe_html(args["html"]):
            return block("UNSAFE_OUTPUT")

    # =========================================================
    # 8. EVERYTHING PASSED
    # =========================================================

    return allow()


@app.get("/")
def root():
    return {
        "service": "action-firewall",
        "status": "ok",
    }
