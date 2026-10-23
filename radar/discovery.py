import asyncio
from dataclasses import dataclass, field
from html.parser import HTMLParser
import ipaddress
import json
import secrets
from urllib.parse import quote, urljoin, urlsplit

import dns.asyncresolver
import dns.exception
import dns.resolver
import httpx

from radar.models import Target, parse_targets
from radar.network import Stopped, gather_workers
from radar.tls import inspect_tls


@dataclass
class DNSResult:
    ips: set = field(default_factory=set)
    statuses: dict = field(default_factory=dict)
    cnames: set = field(default_factory=set)

    def document(self):
        return {"ips": sorted(self.ips), "statuses": self.statuses, "cnames": sorted(self.cnames)}


async def resolve_details(host, timeout=5):
    try:
        return DNSResult({str(ipaddress.ip_address(host))}, {"literal": "OK"})
    except ValueError:
        pass
    resolver = dns.asyncresolver.Resolver()  # preserves corporate/split DNS
    result = DNSResult()

    async def query(kind):
        for attempt in range(2):
            try:
                answers = await resolver.resolve(host, kind, lifetime=timeout)
                result.statuses[kind] = "OK"
                result.ips.update(str(answer) for answer in answers)
                canonical = str(answers.canonical_name).rstrip(".")
                if canonical != host:
                    result.cnames.add(canonical)
                return
            except dns.resolver.NXDOMAIN:
                result.statuses[kind] = "NXDOMAIN"
                return
            except dns.resolver.NoAnswer:
                result.statuses[kind] = "NODATA"
                return
            except dns.resolver.NoNameservers as exc:
                message = str(exc).upper()
                result.statuses[kind] = "REFUSED" if "REFUSED" in message else "SERVFAIL" if "SERVFAIL" in message else "NO_NAMESERVERS"
            except dns.exception.Timeout:
                result.statuses[kind] = "TIMEOUT"
            except dns.exception.DNSException:
                result.statuses[kind] = "DNS_ERROR"
                return
            if not attempt:
                await asyncio.sleep(0.15)
    await asyncio.gather(query("A"), query("AAAA"))
    return result


async def resolve(host, timeout=5):
    return (await resolve_details(host, timeout)).ips


def candidate_name(raw, domain):
    name = raw.strip().lower().rstrip(".")
    if "*" in name or not name.endswith("." + domain):
        return None
    try:
        return parse_targets(name)[0].host
    except (ValueError, UnicodeError):
        return None


class PublicLinks(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.hrefs = []

    def handle_starttag(self, tag, attrs):
        if tag == "a" and len(self.hrefs) < 1000:
            href = dict(attrs).get("href")
            if href:
                self.hrefs.append(href)


async def public_link_names(domain, network, log):
    """Find bounded same-domain hostnames linked from the supplied homepage."""
    for url in (f"https://{domain}/", f"http://{domain}/"):
        try:
            try:
                response = await network.request("GET", url, limit=524288)
            finally:
                # Discovery must not prime the scan's cookie jar. A PHP-based
                # site may set its only recognizable cookie on the first GET.
                network.client.cookies.clear()
            final_host = (urlsplit(response.url).hostname or "").lower()
            content_type = response.headers.get("content-type", "").lower()
            same_site = final_host == domain or final_host == "www." + domain or (domain.startswith("www.") and final_host == domain[4:])
            if response.status != 200 or not same_site or (content_type and "html" not in content_type):
                continue
            links = PublicLinks()
            links.feed(response.text)
            names = set()
            for href in links.hrefs:
                try:
                    host = urlsplit(urljoin(response.url, href)).hostname or ""
                    name = candidate_name(host, domain)
                    if name:
                        names.add(name)
                except ValueError:
                    continue
            log(f"Public site links: {len(names)} subdomain candidates from {url}"
                + (" (partial page)." if response.truncated else "."))
            return names
        except Stopped:
            raise
        except Exception as exc:
            log(f"Public site links from {url}: PARTIAL / {type(exc).__name__}.")
    return set()


async def passive_names(domain, network, log, max_pages=50, with_sources=False):
    names = {}
    for label, base in (
        ("crt.sh", f"https://crt.sh/?q=%25.{quote(domain)}&output=json"),
        ("Cert Spotter", f"https://api.certspotter.com/v1/issuances?domain={quote(domain)}&include_subdomains=true&expand=dns_names"),
    ):
        cursor, seen = None, set()
        complete = False
        try:
            for page in range(max_pages if label == "Cert Spotter" else 1):
                url = base + ("&after=" + quote(cursor) if cursor else "")
                try:
                    response = await network.request("GET", url, limit=2_000_000)
                except (TimeoutError, OSError, httpx.TransportError):
                    if label != "crt.sh":
                        raise
                    log("crt.sh: first request failed; retrying once.")
                    response = await network.request("GET", url, limit=2_000_000)
                if response.status != 200 or response.truncated:
                    log(f"{label}: PARTIAL (HTTP {response.status}, truncated={response.truncated}).")
                    break
                rows = json.loads(response.text)
                if not isinstance(rows, list):
                    raise ValueError("Unexpected provider response")
                for row in rows:
                    values = row.get("name_value", "").splitlines() if label == "crt.sh" else row.get("dns_names", [])
                    for raw in values:
                        name = candidate_name(raw, domain)
                        if name:
                            names.setdefault(name, set()).add(label)
                if label == "crt.sh" or not rows:
                    complete = True
                    break
                cursor = str(rows[-1].get("id", ""))
                if not cursor or cursor in seen:
                    log(f"{label}: PARTIAL (missing or repeated pagination cursor).")
                    break
                seen.add(cursor)
            log(f"{label}: {'RETRIEVED' if complete else 'PARTIAL'}; {len(names)} cumulative candidates. Provider coverage is not exhaustive.")
        except Stopped:
            raise
        except Exception as exc:
            log(f"{label}: PARTIAL / {type(exc).__name__}.")
    try:
        response = await network.request("GET", f"https://api.hackertarget.com/hostsearch/?q={quote(domain)}", limit=2_000_000)
        if response.status != 200 or response.truncated:
            log(f"HackerTarget: PARTIAL (HTTP {response.status}, truncated={response.truncated}).")
        else:
            lines = [line.strip() for line in response.text.splitlines() if line.strip()]
            # Hostsearch is a bounded public corpus, not a live DNS result.
            if len(lines) == 1 and "," not in lines[0]:
                log(f"HackerTarget: PARTIAL ({lines[0][:100]}).")
            else:
                for line in lines:
                    name = candidate_name(line.partition(",")[0], domain)
                    if name:
                        names.setdefault(name, set()).add("HackerTarget")
                log(f"HackerTarget: {'PARTIAL (public result cap)' if len(lines) >= 500 else 'RETRIEVED'}; {len(names)} cumulative candidates.")
    except Stopped:
        raise
    except Exception as exc:
        log(f"HackerTarget: PARTIAL / {type(exc).__name__}.")
    return names if with_sources else set(names)


async def subdomain_center_names(domain, network, log):
    """Read one keyless passive-source page; Radar validates liveness later."""
    try:
        response = await network.request(
            "GET", f"https://api.subdomain.center/?domain={quote(domain)}", follow=False,
            limit=2_000_000)
        if response.status != 200 or response.truncated:
            log(f"Subdomain Center: PARTIAL (HTTP {response.status}, truncated={response.truncated}).")
            return {}
        payload = json.loads(response.text)
        if not isinstance(payload, list):
            raise ValueError("Unexpected provider response")
        names = {}
        for raw in payload:
            if isinstance(raw, str):
                name = candidate_name(raw, domain)
                if name:
                    names.setdefault(name, set()).add("Subdomain Center")
        partial = response.headers.get("x-truncated", "").lower() == "true" or len(payload) >= 500
        log(f"Subdomain Center: {'PARTIAL (anonymous result cap)' if partial else 'RETRIEVED'}; "
            f"{len(names)} candidates. Public records are not proof of a live site.")
        return names
    except Stopped:
        raise
    except Exception as exc:
        log(f"Subdomain Center: PARTIAL / {type(exc).__name__}.")
        return {}


async def thc_names(domain, network, log):
    """Read up to five pages of the public IP.THC.ORG subdomain index."""
    names, seen = {}, set()
    cursor, complete = "", False
    try:
        for _ in range(5):
            body = json.dumps({"domain": domain, "page_state": cursor, "limit": 100}).encode()
            response = await network.request(
                "POST", "https://ip.thc.org/api/v1/lookup/subdomains", follow=False,
                limit=2_000_000, headers={"Content-Type": "application/json"}, content=body)
            if response.status != 200 or response.truncated:
                log(f"IP.THC.ORG: PARTIAL (HTTP {response.status}, truncated={response.truncated}).")
                return names
            payload = json.loads(response.text)
            if not isinstance(payload, dict) or not isinstance(payload.get("domains"), list):
                raise ValueError("Unexpected provider response")
            for row in payload["domains"]:
                if isinstance(row, dict) and isinstance(row.get("domain"), str):
                    name = candidate_name(row["domain"], domain)
                    if name:
                        names.setdefault(name, set()).add("IP.THC.ORG")
            next_cursor = payload.get("next_page_state") or ""
            if not next_cursor:
                complete = True
                break
            if not isinstance(next_cursor, str) or next_cursor in seen or next_cursor == cursor:
                break
            seen.add(next_cursor)
            cursor = next_cursor
        log(f"IP.THC.ORG: {'RETRIEVED' if complete else 'PARTIAL (page cap or cursor)'}; "
            f"{len(names)} candidates. Indexed names are not proof of a live site.")
    except Stopped:
        raise
    except Exception as exc:
        log(f"IP.THC.ORG: PARTIAL / {type(exc).__name__}.")
    return names


async def discover(options, network, control, emit):
    discovered = {(t.host, t.url): {"target": t, "source": {"input"}, "ips": set(),
                                   "scope_roots": {t.host}} for t in options.targets}
    roots = sorted({t.host for t in options.targets})
    log = lambda message: emit({"type": "log", "message": message})
    for root in roots:
        await control.checkpoint()
        try:
            ipaddress.ip_address(root)
            continue
        except ValueError:
            pass
        candidates = {}
        if options.tls_names:
            seed = next((t.url for t in options.targets if t.host == root and t.url and t.url.startswith("https://")), f"https://{root}/")
            certificate = await inspect_tls(seed, options.timeout)
            for raw in certificate.get("sans", []):
                name = candidate_name(raw, root)
                if name:
                    candidates.setdefault(name, set()).add("TLS SAN")
            log(f"TLS SAN {seed}: {certificate['status']}; certificate names are candidates, not proof of ownership or liveness.")
        if options.passive_dns:
            for name, sources in (await passive_names(root, network, log, options.ct_pages, True)).items():
                candidates.setdefault(name, set()).update(sources)
            for name, sources in (await subdomain_center_names(root, network, log)).items():
                candidates.setdefault(name, set()).update(sources)
            for name, sources in (await thc_names(root, network, log)).items():
                candidates.setdefault(name, set()).update(sources)
            for name in await public_link_names(root, network, log):
                candidates.setdefault(name, set()).add("public site link")
        wildcard = set()
        wildcard_probe = None
        if options.active_dns:
            for _ in range(3):
                await control.checkpoint()
                probe = f"radar-{secrets.token_hex(10)}.{root}"
                addresses = await resolve(probe, options.timeout)
                if addresses and wildcard_probe is None:
                    wildcard_probe = probe
                wildcard.update(addresses)
            for word in options.words:
                name = candidate_name(f"{word}.{root}", root)
                if name:
                    candidates.setdefault(name, set()).add("active DNS")
        if wildcard:
            log(f"{root}: wildcard DNS. Ambiguous names retained; an IP match is not proof of a real virtual host.")

        async def batch(entries):
            queue = asyncio.Queue()
            for entry in sorted(entries.items()):
                queue.put_nowait(entry)
            async def worker():
                while not queue.empty():
                    await control.checkpoint()
                    try:
                        name, sources = queue.get_nowait()
                    except asyncio.QueueEmpty:
                        return
                    result = await resolve_details(name, options.timeout)
                    ambiguous = bool(wildcard and result.ips and result.ips <= wildcard)
                    key = (name, None)
                    if key not in discovered:
                        discovered[key] = {"target": Target(name), "source": set(), "ips": result.ips,
                                           "scope_roots": set()}
                    host = discovered[key]
                    host["scope_roots"].add(root)
                    host["source"].update(sources)
                    host["dns"] = result.document()
                    host["wildcard"] = ambiguous
                    # CDN wildcard answers can rotate between several IPs.
                    # Compare the random HTTP response for every resolved name.
                    if wildcard_probe and result.ips:
                        host["wildcard_probe"] = wildcard_probe
                        host["wildcard_root"] = root
                    if ambiguous:
                        host["source"].add("wildcard ambiguous")
                    # Retain historical, NXDOMAIN and temporarily unresolved candidates.
                    emit({"type": "host", "host": name, "ips": sorted(result.ips),
                          "source": sorted(host["source"]), "dns": host["dns"],
                          "wildcard_ambiguous": ambiguous})
                    emit({"type": "dns_tick", "host": name})
            await gather_workers(*(worker() for _ in range(min(options.concurrency, max(1, queue.qsize())))))
        await batch(candidates)
        aliases = {}
        for host in list(discovered.values()):
            for raw in host.get("dns", {}).get("cnames", []):
                name = candidate_name(raw, root)
                if name and (name, None) not in discovered:
                    aliases[name] = {"CNAME"}
        await batch(aliases)
        if options.active_dns and options.recursive_dns:
            # One additional level, capped independently from the wordlist size.
            parents = [h["target"].host for h in discovered.values() if h["ips"] and not h.get("wildcard") and h["target"].host.endswith("." + root)]
            extra = {}
            for parent in sorted(set(parents))[:20]:
                for word in options.words[:50]:
                    name = candidate_name(f"{word}.{parent}", root)
                    if name and (name, None) not in discovered:
                        extra[name] = {"recursive DNS"}
            await batch(extra)
            log(f"Recursive DNS: {len(extra)} candidates (one extra level, max 20 parents × 50 labels).")
    return list(discovered.values())
