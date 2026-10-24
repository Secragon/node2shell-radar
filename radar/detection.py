"""Passive Node.js indicators. These never prove a remote runtime version."""

from html.parser import HTMLParser
import hashlib
import re
from urllib.parse import urljoin, urlsplit

from radar.models import CVE, REMOTE_PATCH_STATUS, assess_version, utc_now
from radar.site_identity import describe_site


NODE_VERSION = re.compile(r"\b(?:node(?:\.js)?|io\.js)[/\s:v-]+v?(\d+\.\d+\.\d+(?:[-+~.a-zA-Z0-9]*)?)\b", re.I)
FRAMEWORK_VERSION = re.compile(
    r"\b(Next\.js|Nuxt(?:\.js)?|SvelteKit|Remix|React Router|Gatsby|Astro|RedwoodJS|SolidStart)\b"
    r"(?:[/\s]+v?(\d+\.\d+\.\d+(?:-[a-zA-Z0-9.-]+)?))?", re.I)
NEXT_EXPORTED_VERSION = re.compile(r"\bversion\s*:\s*function\(\)\s*\{\s*return\s+([a-zA-Z_$][\w$]*)\s*\}")
NEXT_LITERAL_VERSION = re.compile(
    r"\bwindow\.next\s*=\s*\{\s*version\s*:\s*['\"](\d+\.\d+\.\d+(?:-[a-zA-Z0-9.-]+)?)['\"]"
)
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
        self.markers = set()
        self._script = False

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "meta":
            self.meta.append(((attrs.get("name") or "").lower(), attrs.get("content") or ""))
        if tag == "script" and attrs.get("id") == "__NEXT_DATA__":
            self.markers.add("Next.js")
        if tag == "script" and attrs.get("id") == "__NUXT_DATA__":
            self.markers.add("Nuxt")
        if tag == "div" and (attrs.get("id") or "").startswith("__nuxt"):
            self.markers.add("Nuxt")
        if tag == "div" and attrs.get("id") == "___gatsby":
            self.markers.add("Gatsby")
        if tag == "style" and attrs.get("id") == "gatsby-inlined-css":
            self.markers.add("Gatsby")
        if tag == "div" and attrs.get("id") == "redwood-app":
            self.markers.add("RedwoodJS")
        if tag == "link" and "__meteor-css__" in (attrs.get("class") or "").split():
            self.markers.add("Meteor")
        if tag in ("astro-island", "astro-slot") or any(name.startswith("data-astro-cid-") for name in attrs):
            self.markers.add("Astro")
        if attrs.get("id") == "svelte-announcer" or any(
                name.startswith("data-sveltekit-") or name == "sveltekit:prefetch" for name in attrs):
            self.markers.add("SvelteKit")
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
            if ".__next_f.push" in data or "__NEXT_DATA__" in data:
                self.markers.add("Next.js")
            if "window.__NUXT__" in data:
                self.markers.add("Nuxt")
            if any(marker in data for marker in ("__remixContext", "__remixManifest", "__remixRouteModules")):
                self.markers.add("Remix")
            if any(marker in data for marker in ("__reactRouterContext", "__reactRouterManifest")):
                self.markers.add("React Router")
            if "__sveltekit_" in data:
                self.markers.add("SvelteKit")
            if "window.___webpackCompilationHash" in data:
                self.markers.add("Gatsby")


def framework_name(raw):
    return {"next.js": "Next.js", "nuxt": "Nuxt", "nuxt.js": "Nuxt",
            "sveltekit": "SvelteKit", "remix": "Remix", "react router": "React Router",
            "gatsby": "Gatsby", "astro": "Astro", "redwoodjs": "RedwoodJS",
            "solidstart": "SolidStart"}[raw.lower()]


def _authority(url):
    parsed = urlsplit(url)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return (parsed.hostname or "").lower(), port


def _in_scope(url, roots):
    host = (urlsplit(url).hostname or "").lower().rstrip(".")
    return any(host == root or host.endswith("." + root) or
               (root.startswith("www.") and host == root[4:]) for root in roots)


def next_script_urls(response, limit=16):
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
                "/_next/static/" not in parsed.path or not parsed.path.endswith(".js")):
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
    literal = NEXT_LITERAL_VERSION.search(text)
    if literal:
        return literal.group(1)
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
        for name, pattern in (("Express", r"\bExpress\b"), ("Koa", r"\bKoa\b"),
                              ("NestJS", r"\bNestJS\b"), ("Fastify", r"\bFastify\b"),
                              ("Hapi", r"\bHapi\b"), ("AdonisJS", r"\bAdonisJS\b"),
                              ("Sails.js", r"\bSails(?:\.js)?\b"),
                              ("Meteor", r"\bMeteor\b"), ("Hono", r"\bHono\b"),
                              ("Strapi", r"\bStrapi\b")):
            if re.search(pattern, value, re.I):
                technologies.add(name)
                add("framework_header", key, f"{name} response header; Node.js runtime unconfirmed",
                    "weak" if name == "Hono" else "medium")
        if key == "x-powered-by" and re.fullmatch(r"Nest", value.strip(), re.I):
            technologies.add("NestJS")
            add("framework_header", key, "NestJS response header; Node.js runtime unconfirmed", "medium")
        for match in FRAMEWORK_VERSION.finditer(value):
            name = framework_name(match.group(1))
            technologies.add(name)
            if match.group(2):
                technology_versions[name] = match.group(2)
            # A framework header is stronger than a static HTML marker, but
            # still does not prove which runtime serves the response.
            strength = "medium" if key == "x-powered-by" and name in (
                "Next.js", "Nuxt", "SvelteKit", "Remix") else "weak"
            add("framework_header", key, f"{name} response header; Node.js runtime unconfirmed", strength)
    if headers.get("x-nextjs-cache") or headers.get("x-nextjs-prerender"):
        technologies.add("Next.js")
        add("framework_header", "x-nextjs-*", "Next.js header; runtime may be elsewhere", "weak")
    cookie_header = headers.get("set-cookie", "")
    for cookie in re.findall(r"(?:^|[,;]\s*)([!#$%&'*+.^_`|~\w:-]+)=", cookie_header):
        lower = cookie.lower()
        if lower in ("connect.sid", "express:sess", "koa:sess", "sails.sid",
                     "adonis-session", "adonis-session-values"):
            product = {"express:sess": "Express", "koa:sess": "Koa",
                       "sails.sid": "Sails.js", "adonis-session": "AdonisJS",
                       "adonis-session-values": "AdonisJS"}.get(lower)
            if product:
                technologies.add(product)
            add("cookie_name", "set-cookie", f"{cookie} cookie name (value omitted)", "medium")
        elif lower == "next_locale":
            technologies.add("Next.js")
            add("cookie_name", "set-cookie", "NEXT_LOCALE cookie name (value omitted)", "weak")

    page = Page()
    if "html" in headers.get("content-type", "").lower() and response.text:
        try:
            page.feed(response.text)
        except (ValueError, AssertionError):
            pass
    for name, content in page.meta:
        if name == "generator":
            for match in FRAMEWORK_VERSION.finditer(content):
                product = framework_name(match.group(1))
                technologies.add(product)
                if match.group(2):
                    technology_versions[product] = match.group(2)
                add("generator", "meta generator", f"{product} frontend; not runtime proof", "weak")
    if any("/_next/" in path for path in page.paths) or "Next.js" in page.markers:
        technologies.add("Next.js")
        add("frontend", "HTML", "Next.js assets; static hosting is possible", "weak")
    if any("/_nuxt/" in path for path in page.paths) or "Nuxt" in page.markers:
        technologies.add("Nuxt")
        add("frontend", "HTML", "Nuxt assets; static hosting is possible", "weak")
    asset_markers = {"SvelteKit": "/_app/immutable/", "Astro": "/_astro/",
                     "Gatsby": "/page-data/app-data.json"}
    for product in ("Remix", "React Router", "SvelteKit", "Astro", "Gatsby",
                    "Meteor", "RedwoodJS"):
        asset_marker = asset_markers.get(product)
        if product in page.markers or (asset_marker and any(asset_marker in path for path in page.paths)):
            technologies.add(product)
            add("frontend", "HTML", f"{product} markup; static or alternate hosting is possible", "weak")

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


def host_neutral_digest(response):
    """Hash a page template after replacing the requested hostname it echoes."""
    hostname = urlsplit(response.url).hostname
    if not hostname or response.status <= 0 or response.truncated:
        return None
    pattern = re.compile(re.escape(hostname), re.I)
    if not pattern.search(response.text):
        return None
    template = pattern.sub("{requested-host}", response.text)
    return hashlib.sha256(template.encode("utf-8")).hexdigest()


def fingerprint(response, scope_hosts=()):
    scope_hosts = tuple(scope_hosts)
    observations = [observe(hop) for hop in response.history] + [observe(response)]
    original = _authority(observations[0]["url"])
    final = _authority(response.url)
    final_in_scope = _in_scope(response.url, scope_hosts)
    external_redirect = final != original and not final_in_scope
    target = final if final != original and final_in_scope else original
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
    if node != "DETECTED" and verdict == "Fixed version":
        verdict, reason = "Unconfirmed", "The reported version is not tied to a confirmed Node.js runtime."
    if target != final:
        verdict, reason = "Unconfirmed", "The request redirected outside the assessed site."
    if node == "NOT_ESTABLISHED":
        verdict, reason = "Unconfirmed", "No Node.js runtime evidence was found in public HTTP responses."
    return {
        "observed_at": utc_now(), "final_url": response.url,
        "site_url": response.url if target == final else observations[0]["url"],
        "external_redirect": external_redirect,
        "content_sha256": hashlib.sha256(response.text.encode("utf-8")).hexdigest()
                          if response.status > 0 and not response.truncated else None,
        "host_neutral_sha256": host_neutral_digest(response),
        "site_identity": describe_site(response),
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
        "decoder_patch_status": REMOTE_PATCH_STATUS,
    }
