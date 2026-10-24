"""Targets, scan options and Node.js version assessment."""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from importlib.resources import files
import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit


CVE = "CVE-2026-111497"
REMOTE_PATCH_STATUS = "Unverified remotely"
FIXED = {22: (22, 23, 4), 24: (24, 22, 1), 26: (26, 12, 1)}
WEB_PORTS = (80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 8081, 9000)


def default_words():
    return [word.strip() for word in files("radar").joinpath("data/subdomains.txt").read_text(encoding="utf-8").splitlines()
            if word.strip() and not word.startswith("#")]


def utc_now():
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class Target:
    host: str
    url: str | None = None


def parse_targets(text: str) -> list[Target]:
    targets = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        explicit = "://" in line
        parsed = urlsplit(line if explicit else "//" + line)
        if explicit and parsed.scheme not in ("http", "https"):
            raise ValueError(f"Unsupported protocol: {line}")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("URLs with credentials are not supported.")
        if not parsed.hostname:
            raise ValueError(f"Missing hostname: {line}")
        host = parsed.hostname.rstrip(".").encode("idna").decode("ascii").lower()
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if len(host) > 253 or any(
                not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part)
                for part in host.split(".")
            ):
                raise ValueError(f"Invalid hostname: {host}")
        port = parsed.port
        if not explicit and (parsed.path not in ("", "/") or parsed.query):
            raise ValueError(f"Include http:// or https:// for a path: {line}")
        url = None
        if explicit or port:
            scheme = parsed.scheme if explicit else ("https" if port in (443, 8443) else "http")
            authority = f"[{host}]" if ":" in host else host
            if port:
                authority += f":{port}"
            url = urlunsplit((scheme, authority, parsed.path or "/", parsed.query, ""))
        targets[(host, url)] = Target(host, url)
    if not targets:
        raise ValueError("Enter at least one domain or URL.")
    return list(targets.values())


@dataclass
class ScanOptions:
    targets: list[Target]
    passive_dns: bool = True
    active_dns: bool = True
    extra_ports: bool = False
    ports: list[int] = field(default_factory=lambda: list(WEB_PORTS))
    words: list[str] = field(default_factory=default_words)
    concurrency: int = 8
    timeout: float = 7.0
    interval: float = 0.35
    verify_tls: bool = True
    crawl: bool = False
    max_pages: int = 12
    recursive_dns: bool = False
    ct_pages: int = 50
    tls_names: bool = True
    all_addresses: bool = False
    active_check: bool = False

    def to_dict(self):
        return asdict(self)


def endpoints(target: Target, options: ScanOptions) -> list[str]:
    host = f"[{target.host}]" if ":" in target.host else target.host
    urls = [target.url] if target.url else [f"https://{host}/", f"http://{host}/"]
    if options.extra_ports:
        for port in options.ports:
            schemes = ("https",) if port == 443 else ("http",) if port == 80 else ("http", "https")
            urls.extend(f"{scheme}://{host}:{port}/" for scheme in schemes)
    unique = {}
    for url in urls:
        parsed = urlsplit(url)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        unique[(parsed.scheme, parsed.hostname, port, parsed.path, parsed.query)] = url
    return list(unique.values())


def assess_version(version: str | None) -> tuple[str, str]:
    """Assess a reported HTTP version without treating it as build verification."""
    if not version:
        return "Unconfirmed", "The running Node.js version is unknown."
    match = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)([-+~.a-zA-Z0-9]*)", version.strip())
    if not match:
        return "Unconfirmed", "The version string could not be parsed."
    major, minor, patch = map(int, match.groups()[:3])
    if match.group(4):
        return "Unconfirmed", "A vendor or prerelease build needs package-specific verification."
    fixed = FIXED.get(major)
    if fixed:
        if (major, minor, patch) >= fixed:
            return "Fixed version", (
                "The HTTP response reports a Node.js version at or after the upstream fix. "
                "The serving process and its selected Brotli decoder have not been verified.")
        return "At risk", (
            "The HTTP response reports a Node.js version before the upstream fix. "
            "A vendor backport or different selected decoder may change its actual patch state.")
    if major < 22 or major in (23, 25):
        return "Unconfirmed", "The HTTP response reports an unsupported branch outside the published fix matrix."
    return "Unconfirmed", "The HTTP response reports a branch outside the published fix matrix."
