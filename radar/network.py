import asyncio
from dataclasses import dataclass, field
import time
from urllib.parse import urlsplit

import httpx


class Stopped(Exception):
    pass


async def gather_workers(*coroutines):
    tasks = [asyncio.create_task(coroutine) for coroutine in coroutines]
    try:
        return await asyncio.gather(*tasks)
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


@dataclass
class Response:
    url: str
    status: int
    headers: dict[str, str]
    text: str
    elapsed_ms: int
    redirects: list[str] = field(default_factory=list)
    truncated: bool = False
    history: list["Response"] = field(default_factory=list)


class Network:
    def __init__(self, options, control, transport=None):
        self.options = options
        self.transport = transport
        self.control = control
        self.client = httpx.AsyncClient(
            verify=options.verify_tls, timeout=options.timeout,
            headers={"User-Agent": "Mozilla/5.0 (compatible; Node2Shell-Radar; +https://github.com/Secragon/node2shell-radar)",
                     "Accept-Encoding": "identity"},
            follow_redirects=False, transport=transport, trust_env=False,
            limits=httpx.Limits(max_connections=options.concurrency),
        )
        self.locks = {}
        self.last_request = {}

    async def request(self, method, url, *, limit=131072, follow=True, **kwargs):
        async with asyncio.timeout(self.options.timeout * 4):
            return await self._request(method, url, limit=limit, follow=follow, **kwargs)

    async def request_ip(self, method, url, address, *, limit=131072, **kwargs):
        # Separate pool avoids reusing a TLS connection for another SNI on a shared IP.
        child = Network(self.options, self.control, self.transport)
        child.locks, child.last_request = self.locks, self.last_request
        original = httpx.URL(url)
        child.rate_host = original.host
        authority = original.netloc.decode("ascii")
        try:
            headers = {"Host": authority, **kwargs.pop("headers", {})}
            kwargs.pop("follow", None)
            response = await child.request(method, str(original.copy_with(host=address)), follow=False, limit=limit,
                                           headers=headers, extensions={"sni_hostname": original.host}, **kwargs)
            response.url = url
            return response
        finally:
            await child.close()

    async def _request(self, method, url, *, limit, follow, **kwargs):
        """Bound streamed data; manually handle redirects to throttle every host."""
        started = time.monotonic()
        redirects = []
        history = []
        for hop in range(4):
            await self.control.checkpoint()
            host = getattr(self, "rate_host", None) or urlsplit(url).hostname
            lock = self.locks.setdefault(host, asyncio.Lock())
            async with lock:
                wait = self.options.interval - (time.monotonic() - self.last_request.get(host, 0))
                if wait > 0:
                    await asyncio.sleep(wait)
                await self.control.checkpoint()
                self.last_request[host] = time.monotonic()
                async with self.client.stream(method, url, **kwargs) as response:
                    headers = dict(response.headers)
                    body = bytearray()
                    async for chunk in response.aiter_bytes(chunk_size=16384):
                        await self.control.checkpoint()
                        body.extend(chunk[:max(0, limit - len(body))])
                        if len(body) >= limit:
                            break
                    result = Response(str(response.url), response.status_code, headers,
                                      body.decode("utf-8", errors="replace"),
                                      int((time.monotonic() - started) * 1000), redirects.copy(), len(body) >= limit,
                                      history.copy())
                    if follow and response.is_redirect and response.headers.get("location") and hop < 3:
                        next_url = response.url.join(response.headers["location"])
                        if next_url.scheme not in ("http", "https"):
                            return result
                        # Retain bounded hop responses in memory, not in saved reports.
                        history.append(Response(result.url, result.status, result.headers,
                                                result.text, result.elapsed_ms, truncated=result.truncated))
                        redirects.append(str(next_url))
                        url = str(next_url)
                        if response.status_code == 303 or (response.status_code in (301, 302) and method == "POST"):
                            method, kwargs = "GET", {}
                        continue
                    return result
        return result

    async def close(self):
        await self.client.aclose()
