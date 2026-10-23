"""Bounded passive clues for deciding whether URL variants serve one website."""

from hashlib import blake2b, sha256
from html.parser import HTMLParser
import re
from urllib.parse import urljoin, urlsplit, urlunsplit


class SitePage(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.hidden = None
        self.in_title = False
        self.title = []
        self.visible = []
        self.canonical = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag in ("script", "style", "template", "svg", "noscript"):
            self.hidden = tag
        if tag == "title":
            self.in_title = True
        if tag == "link" and "canonical" in (attrs.get("rel") or "").lower():
            self.canonical = attrs.get("href")

    def handle_endtag(self, tag):
        if tag == self.hidden:
            self.hidden = None
        if tag == "title":
            self.in_title = False

    def handle_data(self, data):
        if self.hidden:
            return
        if self.in_title:
            self.title.append(data)
        self.visible.append(data)


def origin(url):
    parsed = urlsplit(url)
    return urlunsplit((parsed.scheme, parsed.netloc, "/", "", "")) if parsed.hostname else ""


def describe_site(response):
    """Store only a small sketch of public text, never the page body."""
    if response.status <= 0:
        return None
    content_type = response.headers.get("content-type", "").lower()
    if content_type and "html" not in content_type:
        return None
    parser = SitePage()
    try:
        parser.feed(response.text)
    except (ValueError, AssertionError):
        return None
    title = re.sub(r"\s+", " ", " ".join(parser.title)).strip().casefold()
    tokens = re.findall(r"[^\W_]+", " ".join(parser.visible).casefold())
    shingles = {" ".join(tokens[index:index + 4]) for index in range(max(0, len(tokens) - 3))}
    sketch = sorted(blake2b(shingle.encode("utf-8"), digest_size=8).hexdigest()
                    for shingle in shingles)[:256]
    canonical = ""
    if parser.canonical:
        try:
            canonical = origin(urljoin(response.url, parser.canonical))
        except ValueError:
            pass
    return {"title": title[:160], "canonical": canonical,
            "sketch": sketch, "shingles": len(shingles),
            "prefix_sha256": sha256(response.text.encode("utf-8")).hexdigest(),
            "captured_chars": len(response.text), "truncated": response.truncated}


def equivalent_pages(left, right):
    """Require direct positive evidence before folding apex/www host variants."""
    if left.get("http_status") != 200 or right.get("http_status") != 200:
        return False
    first, second = left.get("site_identity") or {}, right.get("site_identity") or {}
    digest_a, digest_b = left.get("content_sha256"), right.get("content_sha256")
    if digest_a and digest_a == digest_b and min(first.get("captured_chars", 512),
                                                 second.get("captured_chars", 512)) >= 512:
        return True
    if (first.get("prefix_sha256") and first["prefix_sha256"] == second.get("prefix_sha256") and
            min(first.get("captured_chars", 0), second.get("captured_chars", 0)) >= 4096):
        return True
    a, b = set(first.get("sketch") or ()), set(second.get("sketch") or ())
    same_title = len(first.get("title", "")) >= 8 and first.get("title") == second.get("title")
    if (min(len(a), len(b)) >= 8 and same_title and
            min(first.get("captured_chars", 0), second.get("captured_chars", 0)) >= 2048 and
            len(a & b) / len(a | b) >= 0.9):
        return True
    if min(len(a), len(b)) < 20:
        return False
    similarity = len(a & b) / len(a | b)
    if similarity >= 0.72:
        return True
    same_canonical = bool(first.get("canonical") and first.get("canonical") == second.get("canonical"))
    return similarity >= 0.45 and (same_title or same_canonical)
