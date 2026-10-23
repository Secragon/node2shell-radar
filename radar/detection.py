"""Passive Node.js indicators. These never prove a remote runtime version."""

from html.parser import HTMLParser
import hashlib
import re
from urllib.parse import urljoin, urlsplit

from radar.models import CVE, assess_version, utc_now


NODE_VERSION = re.compile(r"\b(?:node(?:\.js)?|io\.js)[/\s:v-]+v?(\d+\.\d+\.\d+(?:[-+~.a-zA-Z0-9]*)?)\b", re.I)
NEXT_HEADER_VERSION = re.compile(r"\bNext\.js[/\s]+v?(\d+\.\d+\.\d+(?:-[a-zA-Z0-9.-]+)?)\b", re.I)
NEXT_EXPORTED_VERSION = re.compile(r"\bversion\s*:\s*function\(\)\s*\{\s*return\s+([a-zA-Z_$][\w$]*)\s*\}")
PROXIES = (("Cloudflare", "cf-ray"), ("CloudFront", "x-amz-cf-id"),
           ("Varnish", "x-varnish"), ("Fastly", "x-served-by"),
           ("Imperva", "x-iinfo"))


class Page(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.meta = []
        self.paths = []
        self.scripts = []
        self.inline = []
        self._script = False

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "meta":
            self.meta.append(((attrs.get("name") or "").lower(), attrs.get("content") or ""))
        if tag in ("script", "link", "img"):
            value = attrs.get("src") or attrs.get("href")
            if value:
                self.paths.append(value[:500])
                if tag == "script":
                    self.scripts.append(value[:500])
        if tag == "script" and not attrs.get("src"):
            self._script = True

    def handle_endtag(self, tag):
        if tag == "script":
            self._script = False

    def handle_data(self, data):
        if self._script:
            self.inline.append(data[:3000])


def _authority(url):
    parsed = urlsplit(url)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return (parsed.hostname or "").lower(), port


def _in_scope(url, roots):
    host = (urlsplit(url).hostname or "").lower().rstrip(".")
    return any(host == root or host.endswith("." + root) or
               (root.startswith("www.") and host == root[4:]) for root in roots)


def next_script_urls(response, limit=8):
    """Bound same-origin Next.js assets used by the ordinary page load."""
    if "html" not in response.headers.get("content-type", "").lower():
        return []
    page = Page()
    try:
        page.feed(response.text)
    except (ValueError, AssertionError):
        pass
    original = urlsplit(response.url)
    urls = []
    for path in page.scripts:
        url = urljoin(response.url, path)
        parsed = urlsplit(url)
        if (parsed.scheme != original.scheme or parsed.netloc != original.netloc or
                not parsed.path.startswith("/_next/static/") or not parsed.path.endswith(".js")):
            continue
        if url not in urls:
            urls.append(url)
        if len(urls) >= limit:
            break
    return urls


def next_version_from_script(text):
    """Read the exported Next.js client version without executing JavaScript."""
    if "window.next" not in text:
        return None
    for exported in NEXT_EXPORTED_VERSION.finditer(text):
        name = re.escape(exported.group(1))
        assignment = re.search(
            rf"\b(?:let|const|var)\s+{name}\s*=\s*['\"](\d+\.\d+\.\d+(?:-[a-zA-Z0-9.-]+)?)['\"]",
            text[exported.end():exported.end() + 2400],
        )
        if assignment:
            return assignment.group(1)
    return None


def observe(response):
    headers = {key.lower(): value for key, value in response.headers.items()}
    evidence, versions, technologies, technology_versions = [], set(), set(), {}

    def add(kind, source, value, strength):
        item = {"type": kind, "source": source, "value": value,
                "strength": strength, "url": response.url}
        if item not in evidence:
            evidence.append(item)

    for key in ("x-powered-by", "server", "x-runtime", "x-node-version"):
        value = headers.get(key, "")[:300]
        if not value:
            continue
        direct = key == "x-node-version" or bool(re.search(r"\b(?:Node(?:\.js)?|io\.js)\b", value, re.I))
        if direct:
            add("runtime_header", key, "Node.js identified in response header", "strong")
            versions.update(match.group(1) for match in NODE_VERSION.finditer(value))
            if key == "x-node-version":
                bare = re.fullmatch(r"v?(\d+\.\d+\.\d+(?:[-+~.a-zA-Z0-9]*)?)", value.strip())
                if bare:
                    versions.add(bare.group(1))
        for name in ("Express", "Koa", "NestJS", "Fastify", "Hapi"):
            if re.search(rf"\b{re.escape(name)}\b", value, re.I):
                technologies.add(name)
                add("framework_header", key, f"{name} response header", "medium")
        if re.search(r"\bNext\.js\b", value, re.I):
            technologies.add("Next.js")
            next_version = NEXT_HEADER_VERSION.search(value)
            if next_version:
                technology_versions["Next.js"] = next_version.group(1)
            # Next.js emits X-Powered-By on served responses by default. A
            # header is stronger than static asset paths, though a proxy or
            # alternate runtime can still produce it.
            strength = "medium" if key == "x-powered-by" else "weak"
            add("framework_header", key, "Next.js response header; Node.js runtime is likely but unconfirmed", strength)
    if headers.get("x-nextjs-cache") or headers.get("x-nextjs-prerender"):
        technologies.add("Next.js")
        add("framework_header", "x-nextjs-*", "Next.js header; runtime may be elsewhere", "weak")
    cookie_header = headers.get("set-cookie", "")
    for cookie in re.findall(r"(?:^|[,;]\s*)([!#$%&'*+.^_`|~\w-]+)=", cookie_header):
        if cookie.lower() in ("connect.sid", "express:sess", "koa:sess"):
            add("cookie_name", "set-cookie", f"{cookie} cookie name (value omitted)", "medium")

    page = Page()
    if "html" in headers.get("content-type", "").lower() and response.text:
        try:
            page.feed(response.text)
        except (ValueError, AssertionError):
            pass
    for name, content in page.meta:
        if name == "generator" and re.search(r"\b(?:Next\.js|Nuxt|Gatsby)\b", content, re.I):
            product = re.search(r"\b(?:Next\.js|Nuxt|Gatsby)\b", content, re.I).group(0)
            technologies.add(product)
            add("generator", "meta generator", f"{product} frontend; not runtime proof", "weak")
    if any("/_next/" in path for path in page.paths) or "__NEXT_DATA__" in response.text:
        technologies.add("Next.js")
        add("frontend", "HTML", "Next.js assets; static hosting is possible", "weak")
    if any("/_nuxt/" in path for path in page.paths) or "__NUXT__" in response.text:
        technologies.add("Nuxt")
        add("frontend", "HTML", "Nuxt assets; static hosting is possible", "weak")

    return {
        "url": response.url,
        "http_status": response.status,
        "evidence": evidence,
        "reported_versions": sorted(versions),
        "technologies": sorted(technologies),
        "technology_versions": technology_versions,
        "brotli_response": headers.get("content-encoding", "").lower().strip() == "br",
        "proxy": sorted(name for name, marker in PROXIES if marker in headers),
        "truncated": response.truncated,
    }


def fingerprint(response, scope_hosts=()):
    observations = [observe(hop) for hop in response.history] + [observe(response)]
    original = _authority(observations[0]["url"])
    final = _authority(response.url)
    target = final if final != original and _in_scope(response.url, scope_hosts) else original
    owned = [item for item in observations if _authority(item["url"]) == target]
    evidence = [entry for item in owned for entry in item["evidence"]]
    versions = sorted({version for item in owned for version in item["reported_versions"]})
    version = versions[0] if len(versions) == 1 else None
    technology_version_sets = {}
    for item in owned:
        for name, reported in item["technology_versions"].items():
            technology_version_sets.setdefault(name, set()).add(reported)
    technology_versions = {name: next(iter(reported)) for name, reported in technology_version_sets.items()
                           if len(reported) == 1}
    strong = any(item["strength"] == "strong" for item in evidence)
    medium = any(item["strength"] == "medium" for item in evidence)
    weak = any(item["strength"] == "weak" for item in evidence)
    node = "DETECTED" if strong else "LIKELY" if medium else "POSSIBLE" if weak else "NOT_ESTABLISHED"
    verdict, reason = assess_version(version)
    if len(versions) > 1:
        verdict, reason = "Unconfirmed", "Conflicting Node.js versions were reported."
    if node != "DETECTED" and verdict == "Fixed version reported":
        verdict, reason = "Unconfirmed", "The reported version is not tied to a confirmed Node.js runtime."
    if target != final:
        verdict, reason = "Unconfirmed", "The request redirected outside the assessed site."
    if node == "NOT_ESTABLISHED":
        verdict, reason = "Unconfirmed", "No Node.js runtime evidence was found in public HTTP responses."
    return {
        "observed_at": utc_now(), "final_url": response.url,
        "site_url": response.url if target == final else observations[0]["url"],
        "content_sha256": hashlib.sha256(response.text.encode("utf-8")).hexdigest()
                          if response.status == 200 and not response.truncated else None,
        "http_status": response.status, "elapsed_ms": response.elapsed_ms,
        "node": node, "confidence": "high" if strong else "medium" if medium else "low" if weak else "none",
        "version": version, "reported_versions": versions,
        "technologies": sorted({tech for item in owned for tech in item["technologies"]}),
        "technology_versions": technology_versions,
        "brotli_response": any(item["brotli_response"] for item in owned),
        "proxy": sorted({proxy for item in owned for proxy in item["proxy"]}),
        "redirects": response.redirects, "response_observations": observations,
        "detection_partial": any(item["truncated"] for item in owned),
        "server": response.headers.get("server", "")[:300] if target == final else "",
        "evidence": evidence, "cve": CVE,
        "verdict": verdict, "verdict_reason": reason,
    }
