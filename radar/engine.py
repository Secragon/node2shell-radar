"""Bounded domain discovery and passive HTTP assessment."""

import asyncio
import threading
import uuid
from urllib.parse import urlsplit

from radar.crawl import crawl_pages
from radar.detection import fingerprint, next_script_urls, next_version_from_script
from radar.discovery import discover, resolve_details
from radar.models import endpoints, utc_now
from radar.network import Network, Stopped, gather_workers
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


def merge_crawl(base, pages):
    """Collect additional technology clues without treating each path as a new website."""
    rank = {"NOT_ESTABLISHED": 0, "POSSIBLE": 1, "LIKELY": 2, "DETECTED": 3}
    for page in pages:
        found = fingerprint(page, [base["host"]])
        if urlsplit(found["final_url"]).netloc != urlsplit(base["final_url"]).netloc:
            continue
        if rank.get(found["node"], 0) > rank.get(base["node"], 0):
            base["node"] = found["node"]
            base["confidence"] = found["confidence"]
        for evidence in found["evidence"]:
            if evidence not in base["evidence"]:
                base["evidence"].append(evidence)
        base["technologies"] = sorted(set(base["technologies"]) | set(found["technologies"]))
        for name, version in found.get("technology_versions", {}).items():
            base.setdefault("technology_versions", {}).setdefault(name, version)
        base["brotli_response"] = base["brotli_response"] or found["brotli_response"]
        # A second path can have a different backend. Preserve conflicting versions.
        versions = sorted(set(base["reported_versions"]) | set(found["reported_versions"]))
        base["reported_versions"] = versions
        if len(versions) > 1:
            base["version"] = None
            base["verdict"] = "Unconfirmed"
            base["verdict_reason"] = "Different paths reported different Node.js versions."
        elif len(versions) == 1 and not base.get("version"):
            base["version"] = versions[0]
            if found["verdict"] == "At risk":
                base["verdict"], base["verdict_reason"] = found["verdict"], found["verdict_reason"]
            elif found["verdict"] == "Fixed version reported" and base["node"] == "DETECTED":
                base["verdict"], base["verdict_reason"] = found["verdict"], found["verdict_reason"]


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
                "wildcard_candidates": 0, "crawl_partial": 0, "sources": []}
    completed = 0
    try:
        await control.checkpoint()

        def discovery_event(event):
            if event["type"] == "log":
                coverage["sources"].append(event["message"])
            emit(event)

        emit({"type": "stage", "stage": "DNS and public-source discovery", "completed": 0, "total": 0})
        hosts = await discover(options, network, control, discovery_event)
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
                continue
            if host.get("wildcard"):
                coverage["wildcard_candidates"] += 1
            addresses = sorted(host["ips"]) if options.all_addresses else [None]
            for url in endpoints(target, options):
                for address in addresses:
                    item = pending_asset(url, target, host["ips"], host["source"], address)
                    item["dns"] = host["dns"]
                    item["wildcard_ambiguous"] = host.get("wildcard", False)
                    if item["id"] in unique:
                        continue
                    unique.add(item["id"])
                    queue.put_nowait(item)

        total = queue.qsize()
        emit({"type": "stage", "stage": "HTTP and Node.js signals", "completed": 0, "total": total})

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
                    item.update(fingerprint(response, (target.host for target in options.targets)))
                    await enrich_next_version(item, response, network)
                    if options.crawl and response.status == 200:
                        pages, report = await crawl_pages(network, response, options.max_pages, item["connect_ip"])
                        item["crawl"] = report
                        coverage["crawl_partial"] += int(report["partial"])
                        merge_crawl(item, pages)
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
