"""Conservative, non-exploit check for reachable Brotli request parsing."""

from urllib.parse import urlsplit

from radar.network import Stopped


# Complete Brotli streams for b"{}" and b"{" (generated with Node.js zlib).
# Only the JSON is invalid in the second case; neither stream is malformed.
BR_VALID_JSON = bytes.fromhex("8b00807b7d03")
BR_INVALID_JSON = bytes.fromhex("0b00807b03")


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
