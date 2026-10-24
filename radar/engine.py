"""Bounded domain discovery and passive HTTP assessment."""

import asyncio
import threading
import uuid
from urllib.parse import urlsplit

from radar.active import check_active_paths
from radar.crawl import crawl_pages
from radar.detection import fingerprint, next_script_urls, next_version_from_script
from radar.discovery import discover, resolve_details
from radar.models import Target, endpoints, utc_now
from radar.network import Network, Stopped, gather_workers
from radar.site_identity import equivalent_pages
from radar.tls import inspect_tls


class Control:
    def __init__(self):
        self.paused = threading.Event()
        self.stopped = threading.Event()

    async def checkpoint(self):
        while self.paused.is_set():
            if self.stopped.is_set():
                raise Stopped()
            await asyncio.sleep(0.1)
        if self.stopped.is_set():
            raise Stopped()


def pending_asset(url, target, ips=(), source=("input",), connect_ip=None):
    return {"id": url + (f" [IP {connect_ip}]" if connect_ip else ""),
            "url": url, "host": target.host, "connect_ip": connect_ip,
            "ips": sorted(ips), "source": sorted(source), "node": "PENDING",
            "verdict": "Unconfirmed", "verdict_reason": "HTTP check pending.",
            "evidence": [], "version": None, "error": ""}


def wildcard_page_match(item, baseline):
    """A candidate serving the random wildcard page is not a separate site."""
    if (not baseline or not isinstance(item.get("http_status"), int) or
            item["http_status"] != baseline.get("http_status")):
        return False
    if any(item.get(field) != baseline.get(field) for field in
           ("node", "version", "server", "technologies", "technology_versions")):
        return False
    digest = item.get("content_sha256")
    if digest and digest == baseline.get("content_sha256"):
        return True
    neutral_digest = item.get("host_neutral_sha256")
    if neutral_digest and neutral_digest == baseline.get("host_neutral_sha256"):
        return True
    if item["http_status"] == 200:
        return equivalent_pages(item, baseline)
    first, second = item.get("site_identity") or {}, baseline.get("site_identity") or {}
    a, b = set(first.get("sketch") or ()), set(second.get("sketch") or ())
    return bool(first.get("title") and len(first["title"]) >= 8 and
                first["title"] == second.get("title") and
                min(first.get("captured_chars", 0), second.get("captured_chars", 0)) >= 512 and
                min(len(a), len(b)) >= 20 and len(a & b) / len(a | b) >= 0.85)


async def tcp_port_reachable(address, port, timeout):
    """Avoid repeated HTTP timeouts on one unreachable wildcard IP/port."""
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(address, port), timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return True
    except (OSError, TimeoutError):
        return False


async def enrich_next_version(item, response, network):
    """Read a few same-origin page assets for the Next.js client version."""
    if (response.status != 200 or "Next.js" not in item.get("technologies", ()) or
            item.get("technology_versions", {}).get("Next.js")):
        return
    for url in next_script_urls(response):
        try:
            if item.get("connect_ip"):
                script = await network.request_ip("GET", url, item["connect_ip"], limit=262144)
            else:
                script = await network.request("GET", url, limit=262144, follow=False)
        except Stopped:
            raise
        except Exception:
            continue
        if script.status != 200 or urlsplit(script.url).netloc != urlsplit(response.url).netloc:
            continue
        version = next_version_from_script(script.text)
        if version:
            item.setdefault("technology_versions", {})["Next.js"] = version
            item["evidence"].append({"type": "frontend_version", "source": url,
                                     "value": f"Next.js {version} client version; Node.js version unknown",
                                     "strength": "weak", "url": response.url})
            return


async def run_scan(options, control, emit, transport=None):
    network = Network(options, control, transport)
    run_id = str(uuid.uuid4())
    emit({"type": "started", "id": run_id, "started_at": utc_now(), "options": options.to_dict()})
    coverage = {"dns_unresolved": 0, "http_errors": 0, "tls_errors": 0,
                "wildcard_candidates": 0, "wildcard_http_matches": 0,
                "wildcard_tcp_skipped": 0, "crawl_partial": 0, "sources": []}
    completed = 0
    active_tasks = {}
    try:
        await control.checkpoint()
        if not options.all_addresses:
            for target in options.targets:
                for url in endpoints(target, options):
                    emit({"type": "asset", "asset": pending_asset(url, target)})

        def discovery_event(event):
            if event["type"] == "log":
                coverage["sources"].append(event["message"])
            emit(event)

        emit({"type": "stage", "stage": "DNS and public-source discovery", "completed": 0, "total": 0})
        hosts = await discover(options, network, control, discovery_event)
        wildcard_baselines = {}
        for root, probe in sorted({(host["wildcard_root"], host["wildcard_probe"])
                                   for host in hosts if host.get("wildcard_probe")}):
            for scheme in ("https", "http"):
                await control.checkpoint()
                try:
                    response = await network.request("GET", f"{scheme}://{probe}/")
                    wildcard_baselines[(root, scheme)] = fingerprint(response, (root,))
                except Stopped:
                    raise
                except Exception as exc:
                    emit({"type": "log", "message":
                          f"Wildcard HTTP baseline for {root} ({scheme}): {type(exc).__name__}."})
        wildcard_ports = set()
        for host in hosts:
            if host.get("wildcard"):
                for url in endpoints(host["target"], options):
                    parsed = urlsplit(url)
                    port = parsed.port or (443 if parsed.scheme == "https" else 80)
                    wildcard_ports.update((address, port) for address in host["ips"])
        wildcard_tcp = {}
        for address, port in sorted(wildcard_ports):
            await control.checkpoint()
            wildcard_tcp[(address, port)] = await tcp_port_reachable(address, port, options.timeout)
            if not wildcard_tcp[(address, port)]:
                emit({"type": "log", "message":
                      f"Wildcard DNS address {address}:{port}: TCP unavailable; matching candidates are not HTTP sites."})
        queue, unique = asyncio.Queue(), set()
        for host in hosts:
            await control.checkpoint()
            target = host["target"]
            if "dns" not in host:
                details = await resolve_details(target.host, options.timeout)
                host["dns"], host["ips"] = details.document(), details.ips
            if not host["ips"]:
                coverage["dns_unresolved"] += 1
                emit({"type": "log", "message": f"{target.host}: DNS unresolved; no HTTP request sent."})
            if host.get("wildcard"):
                coverage["wildcard_candidates"] += 1
            addresses = sorted(host["ips"]) if options.all_addresses and host["ips"] else [None]
            for url in endpoints(target, options):
                for address in addresses:
                    item = pending_asset(url, target, host["ips"], host["source"], address)
                    item["dns"] = host["dns"]
                    item["scope_roots"] = sorted(host.get("scope_roots", ()))
                    item["wildcard_ambiguous"] = host.get("wildcard", False)
                    if host.get("wildcard_root"):
                        item["wildcard_root"] = host["wildcard_root"]
                    if item["id"] in unique:
                        continue
                    unique.add(item["id"])
                    if not host["ips"]:
                        item.update(node="NOT_ESTABLISHED",
                                    verdict_reason="DNS unresolved; HTTP was not attempted.",
                                    error="DNS unresolved; inspect DNS status. Candidate retained, HTTP not attempted.")
                        emit({"type": "asset", "asset": item})
                        continue
                    parsed = urlsplit(url)
                    port = parsed.port or (443 if parsed.scheme == "https" else 80)
                    if (host.get("wildcard") and
                            all(wildcard_tcp.get((ip, port)) is False for ip in host["ips"])):
                        item.update(node="NOT_ESTABLISHED",
                                    error=f"Wildcard DNS address has no reachable TCP service on port {port}.")
                        coverage["wildcard_tcp_skipped"] += 1
                        emit({"type": "asset", "asset": item})
                        continue
                    queue.put_nowait(item)

        total = queue.qsize()
        emit({"type": "stage", "stage": "HTTP and Node.js signals", "completed": 0, "total": total})

        async def inspect_response(item, response):
            item.update(fingerprint(response, (target.host for target in options.targets)))
            if (item.get("wildcard_root") and wildcard_page_match(
                    item, wildcard_baselines.get((item["wildcard_root"], urlsplit(item["url"]).scheme)))):
                item["wildcard_http_match"] = True
                item["node"] = "NOT_ESTABLISHED"
                item["verdict"] = "Unconfirmed"
                item["verdict_reason"] = "This hostname serves the same page as a random wildcard DNS name."
                coverage["wildcard_http_matches"] += 1
            else:
                await enrich_next_version(item, response, network)
            return item

        async def inspect_active(item, response):
            if not options.active_check:
                return
            if (item.get("wildcard_http_match") or item.get("external_redirect") or
                    item.get("node") not in ("DETECTED", "LIKELY", "POSSIBLE") or
                    item.get("http_status") not in (200, 401, 403)):
                item["active_check"] = {"status": "Skipped", "reason":
                                        "No in-scope Node.js candidate page was available for the request check."}
                return
            key = (response.url, item.get("connect_ip"))
            if key not in active_tasks:
                active_tasks[key] = asyncio.create_task(
                    check_active_paths(network, response.url, item.get("connect_ip"),
                                       item.get("verdict", "Unconfirmed")))
            item["active_check"] = await active_tasks[key]

        async def worker():
            nonlocal completed
            while not queue.empty():
                await control.checkpoint()
                try:
                    item = queue.get_nowait().copy()
                except asyncio.QueueEmpty:
                    return
                try:
                    if item["connect_ip"]:
                        response = await network.request_ip("GET", item["url"], item["connect_ip"])
                    else:
                        response = await network.request("GET", item["url"])
                    await inspect_response(item, response)
                    await inspect_active(item, response)
                    if not item.get("wildcard_http_match") and options.crawl and response.status == 200:
                        pages, report = await crawl_pages(network, response, options.max_pages, item["connect_ip"])
                        item["crawl"] = report
                        coverage["crawl_partial"] += int(report["partial"])
                        for page in pages:
                            child = pending_asset(page.url, Target(item["host"]), item["ips"],
                                                  ["application crawl"], item["connect_ip"])
                            if child["id"] in unique:
                                continue
                            unique.add(child["id"])
                            child["dns"] = item["dns"]
                            child["scope_roots"] = item["scope_roots"]
                            child["wildcard_ambiguous"] = item["wildcard_ambiguous"]
                            if item.get("wildcard_root"):
                                child["wildcard_root"] = item["wildcard_root"]
                            await inspect_response(child, page)
                            emit({"type": "asset", "asset": child})
                except Stopped:
                    raise
                except Exception as exc:
                    message = f"{type(exc).__name__}: {str(exc)[:250]}"
                    item.update(node="NOT_ESTABLISHED", error=message,
                                verdict="Unconfirmed", verdict_reason="The website could not be assessed.",
                                observed_at=utc_now())
                    coverage["http_errors"] += 1
                    if "CERTIFICATE_VERIFY_FAILED" in message or "certificate verify failed" in message:
                        coverage["tls_errors"] += 1
                        item["tls"] = await inspect_tls(item["url"], options.timeout, item["connect_ip"])
                completed += 1
                emit({"type": "asset", "asset": item})
                emit({"type": "progress", "completed": completed, "total": total, "current": item["id"]})

        await gather_workers(*(worker() for _ in range(min(options.concurrency, max(1, total)))))
        emit({"type": "finished", "status": "COMPLETED", "finished_at": utc_now(),
              "completed": completed, "coverage": coverage})
    except Stopped:
        emit({"type": "finished", "status": "STOPPED", "finished_at": utc_now(),
              "completed": completed, "coverage": coverage})
    except Exception as exc:
        emit({"type": "log", "message": f"Scan failed: {type(exc).__name__}: {exc}"})
        emit({"type": "finished", "status": "FAILED", "finished_at": utc_now(),
              "completed": completed, "coverage": coverage})
    finally:
        await network.close()
