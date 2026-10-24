"""Non-exploit checks for reachable Brotli request parsing."""

import json
from urllib.parse import urlsplit, urlunsplit

from radar.network import Stopped


# Complete Brotli streams for b"{}" and b"{" (generated with Node.js zlib).
# Only the JSON is invalid in the second case; neither stream is malformed.
BR_VALID_JSON = bytes.fromhex("8b00807b7d03")
BR_INVALID_JSON = bytes.fromhex("0b00807b03")

# The two login bodies are identical after decompression. The compressed stream
# was generated with Node.js zlib.brotliCompressSync; it is not a malformed stream.
STRAPI_LOGIN_JSON = b'{"identifier":"nobody@node2shell.invalid","password":"WrongPass1"}'
STRAPI_LOGIN_BR = bytes.fromhex(
    "1b4100e88d942eee3242a5c3fff2c81f278551800934987cd870b77803871"
    "c38c7596d099cb01c80d96a1da02a2bff51b738242a4bb3e2be8ddef20"
    "f832ec9af528bf301")


async def check_brotli_json(network, url, connect_ip=None):
    """Compare JSON parser behavior using OPTIONS and complete Brotli streams.

    A positive result shows that some component on the request path handled
    Brotli JSON. It cannot identify the Node.js process or its patch level.
    """
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return {"status": "Skipped", "reason": "No HTTP(S) endpoint to check."}

    async def send(body, encoding=None):
        headers = {"Content-Type": "application/json", "Cache-Control": "no-store"}
        if encoding:
            headers["Content-Encoding"] = encoding
        if connect_ip:
            return await network.request_ip("OPTIONS", url, connect_ip, limit=2048,
                                            headers=headers, content=body)
        return await network.request("OPTIONS", url, limit=2048, follow=False,
                                     headers=headers, content=body)

    try:
        control = await send(b"{")
        if control.status != 400:
            return {"status": "Inconclusive", "reason":
                    f"Uncompressed invalid JSON returned HTTP {control.status}; a JSON parser was not established on this path.",
                    "url": url, "method": "OPTIONS", "http_statuses": [control.status]}
        valid = await send(BR_VALID_JSON, "br")
        if valid.status == 415:
            return {"status": "Rejected here", "reason":
                    "This path rejected a valid Brotli JSON request (HTTP 415). Other routes or outbound fetches may differ.",
                    "url": url, "method": "OPTIONS", "http_statuses": [control.status, valid.status]}
        invalid = await send(BR_INVALID_JSON, "br")
    except Stopped:
        raise
    except Exception as exc:
        return {"status": "Inconclusive", "reason":
                f"The active request could not complete ({type(exc).__name__}).",
                "url": url, "method": "OPTIONS"}

    statuses = [control.status, valid.status, invalid.status]
    if valid.status != 400 and invalid.status == 400:
        return {"status": "Parser observed", "reason":
                "Valid Brotli JSON passed while valid Brotli containing invalid JSON returned HTTP 400, "
                "as did uncompressed invalid JSON. Brotli JSON parsing is reachable on this request path; "
                "this does not establish the Node.js version or vulnerability.",
                "url": url, "method": "OPTIONS", "http_statuses": statuses}
    return {"status": "Inconclusive", "reason":
            f"The three JSON requests returned HTTP {statuses[0]}, {statuses[1]}, and {statuses[2]}; "
            "Brotli parsing could not be established on this path.",
            "url": url, "method": "OPTIONS", "http_statuses": statuses}


def _strapi_login_error(response):
    if response.status not in (400, 401):
        return False
    try:
        error = json.loads(response.text).get("error")
    except (ValueError, AttributeError):
        return False
    if not isinstance(error, dict):
        return False
    return "invalid identifier or password" in str(error.get("message", "")).lower()


async def check_strapi_login(network, url, connect_ip=None):
    """Run Strapi's published paired-login test with a nonexistent identity."""
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return {"name": "Strapi login", "status": "Skipped",
                "reason": "No HTTP(S) endpoint to check."}
    login_url = urlunsplit((parsed.scheme, parsed.netloc, "/api/auth/local", "", ""))

    async def send(body, compressed=False):
        headers = {"Content-Type": "application/json", "Cache-Control": "no-store"}
        if compressed:
            headers["Content-Encoding"] = "br"
        if connect_ip:
            return await network.request_ip("POST", login_url, connect_ip, limit=4096,
                                            headers=headers, content=body)
        return await network.request("POST", login_url, limit=4096, follow=False,
                                     headers=headers, content=body)

    result = {"name": "Strapi login", "url": login_url, "method": "POST"}
    try:
        ordinary = await send(STRAPI_LOGIN_JSON)
        result["http_statuses"] = [ordinary.status]
        # Do not call an arbitrary 400/401 page Strapi, nor send a second login
        # attempt unless the first response identifies Strapi's auth route.
        if not _strapi_login_error(ordinary):
            return {**result, "status": "Inconclusive", "reason":
                    "The ordinary login attempt did not identify Strapi's local-auth route; "
                    "no Brotli login request was sent."}
        compressed = await send(STRAPI_LOGIN_BR, True)
        result["http_statuses"].append(compressed.status)
    except Stopped:
        raise
    except Exception as exc:
        return {**result, "status": "Inconclusive", "reason":
                f"The Strapi login check could not complete ({type(exc).__name__})."}

    if compressed.status == ordinary.status and compressed.text == ordinary.text:
        return {**result, "status": "Parser observed", "reason":
                "The ordinary and valid Brotli-compressed login attempts returned the same Strapi "
                "authentication error. Brotli request parsing is reachable; Node.js patch status is unknown."}
    rejection = compressed.text.lower()
    if compressed.status == 415 or any(marker in rejection for marker in (
            "encoding not supported", "unsupported content-encoding",
            "unsupported content encoding", "brotli-encoded request bodies are not accepted")):
        return {**result, "status": "Rejected here", "reason":
                "The Strapi login route accepted ordinary JSON but rejected the valid Brotli body. "
                "This does not cover other routes or outbound requests."}
    return {**result, "status": "Inconclusive", "reason":
            "The two login responses differed without a clear Brotli rejection; "
            "request parsing could not be established."}


async def check_active_paths(network, url, connect_ip=None, verdict="Unconfirmed"):
    """Run all applicable safe remote checks and combine their evidence."""
    generic = await check_brotli_json(network, url, connect_ip)
    checks = [{"name": "JSON parser route", **generic}]
    checks.append(await check_strapi_login(network, url, connect_ip))
    ranking = {"Skipped": 0, "Inconclusive": 1, "Rejected here": 2,
               "Parser observed": 3}
    strongest = max(checks, key=lambda check: ranking.get(check["status"], -1))
    status = strongest["status"]
    if status == "Parser observed":
        if verdict == "At risk":
            assessment = ("A pre-fix Node.js version was reported and a Brotli request parser "
                          "was reached. Verify the actual runtime build and Brotli library.")
        elif verdict == "Fixed version reported":
            assessment = ("Brotli request parsing was reached, but the reported Node.js version "
                          "is upstream-fixed. Verify the actual runtime build and Brotli library.")
        else:
            assessment = ("Brotli request parsing was reached. The Node.js runtime version "
                          "and patch status remain unconfirmed.")
    elif status == "Rejected here":
        assessment = ("The tested route rejected Brotli requests; other routes and outbound "
                      "Brotli responses are not covered.")
    else:
        assessment = "The active requests did not establish reachable Brotli parsing."
    return {"status": status, "reason": assessment, "assessment": assessment,
            "url": strongest.get("url", url), "method": strongest.get("method"),
            "checks": checks}
