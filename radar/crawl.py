from html.parser import HTMLParser
import re
from urllib.parse import urljoin, urlsplit, urlunsplit
import xml.etree.ElementTree as ET


class Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.values = []

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        # Do not submit forms or crawl state-changing action links automatically.
        if tag == "a" and values.get("href"):
            self.values.append(values["href"])


def page_links(response, origin):
    parser = Links()
    parser.feed(response.text)
    values = parser.values
    if urlsplit(response.url).path.endswith("robots.txt"):
        values += re.findall(r"(?im)^\s*(?:Sitemap|Allow|Disallow):\s*(\S+)", response.text)
    if "xml" in response.headers.get("content-type", "") or urlsplit(response.url).path.endswith(".xml"):
        try:
            xml = ET.fromstring(response.text)
            values += [node.text for node in xml.iter() if node.tag.rsplit("}", 1)[-1] == "loc" and node.text]
        except ET.ParseError:
            pass
    root = urlsplit(origin)
    urls = set()
    for value in values:
        absolute = urlsplit(urljoin(response.url, value))
        if absolute.scheme not in ("http", "https") or absolute.netloc != root.netloc:
            continue
        if re.search(r"logout|delete|remove|unsubscribe|signout", absolute.path, re.I):
            continue
        if absolute.query or "*" in absolute.path or absolute.username:
            continue
        if re.search(r"\.(?:png|jpg|jpeg|gif|svg|css|js|pdf|zip|mp4|woff2?)$", absolute.path, re.I):
            continue
        urls.add(urlunsplit((absolute.scheme, absolute.netloc, absolute.path or "/", "", "")))
    return sorted(urls)


async def crawl_pages(network, first, max_pages=12, connect_ip=None):
    origin = first.url
    seen = {origin}
    pending = list(dict.fromkeys([urljoin(origin, "/robots.txt"), urljoin(origin, "/sitemap.xml")] + page_links(first, origin)))
    pages, errors = [], []
    while pending and len(seen) < max_pages:
        url = pending.pop(0)
        if url in seen:
            continue
        seen.add(url)
        try:
            response = await (network.request_ip("GET", url, connect_ip) if connect_ip else network.request("GET", url, follow=False))
            pages.append(response)
            if response.status == 429:
                break
            if response.status == 200 and len(pending) < max_pages * 10:
                pending.extend(page_links(response, origin))
        except Exception as exc:
            from radar.network import Stopped
            if isinstance(exc, Stopped):
                raise
            errors.append({"url": url, "error": type(exc).__name__})
    return pages, {"visited": len(seen), "remaining": len(set(pending) - seen), "errors": errors,
                   "partial": bool(set(pending) - seen), "limit": max_pages}
