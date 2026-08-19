import re
from urllib.parse import unquote, urlparse

from fastapi import FastAPI, Request

app = FastAPI()

ALLOWED_HOSTS = {
    "cdn-w8v3m8p.example",
    "app-v2q26j3.example",
}

CHANNELS = {"html", "markdown", "url", "sql", "shell"}


def reject(reason):
    return {"safe": False, "reason": reason}


def safe():
    return {"safe": True, "reason": "SAFE"}


def decode_once(text):
    """
    Decode exactly once in this order:
    1. percent escapes
    2. specified HTML entities
    3. \\uXXXX escapes
    """
    decoded = unquote(text)

    entity_map = {
        "&lt;": "<",
        "&gt;": ">",
        "&quot;": '"',
        "&apos;": "'",
        "&amp;": "&",
    }

    # Numeric entities
    decoded = re.sub(
        r"&#(?:x([0-9a-fA-F]+)|([0-9]+));",
        lambda m: chr(int(m.group(1), 16) if m.group(1) else int(m.group(2))),
        decoded,
    )

    # Named entities
    decoded = re.sub(
        r"&(?:lt|gt|quot|apos|amp);",
        lambda m: entity_map[m.group(0)],
        decoded,
        flags=re.IGNORECASE,
    )

    # \uXXXX escapes
    decoded = re.sub(
        r"\\u([0-9a-fA-F]{4})",
        lambda m: chr(int(m.group(1), 16)),
        decoded,
    )

    return decoded


def has_dangerous_scheme(text):
    # Explicit dangerous schemes, allowing whitespace before colon.
    if re.search(
        r"(?i)(?:javascript|data|vbscript)\s*:",
        text,
    ):
        return True

    return False


def extract_urls(channel, text):
    urls = []

    if channel == "html":
        # Quoted src/href attributes only.
        pattern = re.compile(r"""(?is)\b(?:src|href)\s*=\s*(['"])(.*?)\1""")
        for match in pattern.finditer(text):
            urls.append(match.group(2))

    elif channel == "markdown":
        # Target inside ](...)
        pattern = re.compile(r"""\]\(([^)]*)\)""")
        for match in pattern.finditer(text):
            target = match.group(1).strip()

            # Markdown destinations can be enclosed in <...>
            if len(target) >= 2 and target[0] == "<" and target[-1] == ">":
                target = target[1:-1]

            # Remove optional title after whitespace.
            if target:
                if target.startswith(("http://", "https://", "//")):
                    parts = target.split(None, 1)
                    target = parts[0]

            urls.append(target)

    elif channel == "url":
        urls.append(text.strip())

    return urls


def has_bad_url_scheme(url):
    """
    Returns True when:
    - dangerous explicit scheme is present, or
    - extracted absolute URL has a scheme other than http/https.
    """

    if re.search(r"(?i)(?:javascript|data|vbscript)\s*:", url):
        return True

    # Protocol-relative URLs are treated as https.
    candidate = url

    if candidate.startswith("//"):
        candidate = "https:" + candidate

    parsed = urlparse(candidate)

    # An extracted URL with a scheme must be http/https.
    if parsed.scheme:
        if parsed.scheme.lower() not in {"http", "https"}:
            return True

    return False


def is_external_exfil(url):
    """
    Only absolute URLs are checked against the allowlist.
    Relative references are allowed.
    Protocol-relative URLs count as absolute.
    """

    candidate = url

    if candidate.startswith("//"):
        candidate = "https:" + candidate

    parsed = urlparse(candidate)

    # Not an absolute URL.
    if parsed.scheme not in {"http", "https"}:
        return False

    # Compare parsed hostname ONLY.
    hostname = parsed.hostname

    if hostname is None:
        return True

    return hostname.lower() not in ALLOWED_HOSTS


def channel_rule(channel, text):
    """
    Apply channel rules to ORIGINAL text.
    Returns a reason or None.
    """

    if channel == "html":
        # SCRIPT_TAG
        if re.search(
            r"(?is)<\s*(?:script|iframe|object|embed)\b",
            text,
        ):
            return "SCRIPT_TAG"

        # EVENT_HANDLER
        if re.search(
            r"""(?is)\bon[a-zA-Z0-9_-]*\s*=""",
            text,
        ):
            return "EVENT_HANDLER"

        # DANGEROUS_SCHEME
        if has_dangerous_scheme(text):
            return "DANGEROUS_SCHEME"

        urls = extract_urls(channel, text)

        for url in urls:
            if has_bad_url_scheme(url):
                return "DANGEROUS_SCHEME"

        # EXTERNAL_EXFIL
        for url in urls:
            if is_external_exfil(url):
                return "EXTERNAL_EXFIL"

        return None

    if channel == "markdown":
        if has_dangerous_scheme(text):
            return "DANGEROUS_SCHEME"

        urls = extract_urls(channel, text)

        for url in urls:
            if has_bad_url_scheme(url):
                return "DANGEROUS_SCHEME"

        for url in urls:
            if is_external_exfil(url):
                return "EXTERNAL_EXFIL"

        return None

    if channel == "url":
        if has_dangerous_scheme(text):
            return "DANGEROUS_SCHEME"

        urls = extract_urls(channel, text)

        for url in urls:
            if has_bad_url_scheme(url):
                return "DANGEROUS_SCHEME"

        for url in urls:
            if is_external_exfil(url):
                return "EXTERNAL_EXFIL"

        return None

    if channel == "sql":
        if re.search(
            r"""(?is)(?:'|"|;|--|/\*|\bunion\b|\bor\s+1\s*=\s*1\b)""",
            text,
        ):
            return "SQL_METACHAR"

        return None

    if channel == "shell":
        if re.search(r"[;&|`<>]", text):
            return "SHELL_METACHAR"

        if "$(" in text or "${" in text:
            return "SHELL_METACHAR"

        return None

    return "INVALID_SCHEMA"


@app.post("/sanitize-output")
async def sanitize_output(request: Request):

    # ---------------------------------------------------------
    # Rule 1: INVALID_SCHEMA
    # ---------------------------------------------------------
    try:
        body = await request.json()
    except Exception:
        return reject("INVALID_SCHEMA")

    if not isinstance(body, dict):
        return reject("INVALID_SCHEMA")

    if "channel" not in body or "output" not in body:
        return reject("INVALID_SCHEMA")

    channel = body["channel"]
    output = body["output"]

    if channel not in CHANNELS:
        return reject("INVALID_SCHEMA")

    if not isinstance(output, str):
        return reject("INVALID_SCHEMA")

    if len(output) > 20000:
        return reject("INVALID_SCHEMA")

    # ---------------------------------------------------------
    # Rule 2: ENCODED_PAYLOAD
    # Decode once and check decoded version against rules 3+
    # ---------------------------------------------------------
    decoded = decode_once(output)

    if decoded != output:
        decoded_reason = channel_rule(channel, decoded)

        if decoded_reason is not None:
            return reject("ENCODED_PAYLOAD")

    # ---------------------------------------------------------
    # Rule 3+: Apply rules to ORIGINAL output
    # ---------------------------------------------------------
    reason = channel_rule(channel, output)

    if reason is not None:
        return reject(reason)

    return safe()


@app.get("/")
def root():
    return {"status": "ok"}
