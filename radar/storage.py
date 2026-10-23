"""Local sessions, exports and website presentation grouping."""

import csv
import hashlib
import json
from pathlib import Path
import re
import sqlite3
from urllib.parse import urlsplit, urlunsplit

from radar.site_identity import equivalent_pages


class Store:
    def __init__(self, path):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS runs(id TEXT PRIMARY KEY, document TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS assets(run_id TEXT, url TEXT, document TEXT NOT NULL,
                PRIMARY KEY(run_id, url));
        """)
        self.db.commit()

    def save_run(self, run):
        with self.db:
            self.db.execute("INSERT OR REPLACE INTO runs VALUES(?,?)", (run["id"], json.dumps(run)))

    def save_asset(self, run_id, asset):
        with self.db:
            self.db.execute("INSERT OR REPLACE INTO assets VALUES(?,?,?)",
                            (run_id, asset.get("id", asset["url"]), json.dumps(asset)))

    def runs(self):
        return [json.loads(row[0]) for row in self.db.execute("SELECT document FROM runs ORDER BY rowid DESC")]

    def assets(self, run_id):
        return [json.loads(row[0]) for row in self.db.execute("SELECT document FROM assets WHERE run_id=? ORDER BY url", (run_id,))]

    def close(self):
        self.db.close()


EMPTY_CONTENT_SHA256 = hashlib.sha256(b"").hexdigest()


def _site_origin(url):
    parsed = urlsplit(url)
    return urlunsplit((parsed.scheme, parsed.netloc, "/", "", "")) if parsed.hostname else url


def _outside_scope(asset):
    if asset.get("external_redirect"):
        return True
    original = urlsplit(asset.get("url") or "").hostname
    final = urlsplit(asset.get("final_url") or "").hostname
    site = urlsplit(asset.get("site_url") or "").hostname
    return bool(original and final and site == original and final != original)


def _eligible(asset):
    status = asset.get("http_status")
    if (_outside_scope(asset) or asset.get("wildcard_http_match") or
            not isinstance(status, int) or status <= 0):
        return False
    if (status == 200 and asset.get("content_sha256") == EMPTY_CONTENT_SHA256 and
            asset.get("node") == "NOT_ESTABLISHED"):
        return False
    # A shared error page with a framework hint is not proof of a live site.
    return status == 200 or asset.get("node") == "DETECTED"


def _group_key(asset):
    parsed = urlsplit(asset.get("final_url") or asset["url"])
    return (parsed.scheme, (parsed.hostname or "").lower(),
            parsed.port or (443 if parsed.scheme == "https" else 80),
            asset.get("connect_ip"))


def _preference(asset):
    original = urlsplit(asset["url"])
    final = urlsplit(asset.get("final_url") or asset["url"])
    return (asset.get("http_status") != 200,
            original.scheme != final.scheme,
            original.path not in ("", "/"),
            final.scheme != "https",
            (final.hostname or "").startswith("www."),
            asset["url"])


def _same_site_views(first, second):
    a = urlsplit(first.get("final_url") or first["url"])
    b = urlsplit(second.get("final_url") or second["url"])
    if (first.get("http_status") != 200 or second.get("http_status") != 200 or
            first.get("connect_ip") != second.get("connect_ip") or
            not a.hostname or not b.hostname or
            a.port not in (None, 80 if a.scheme == "http" else 443) or
            b.port not in (None, 80 if b.scheme == "http" else 443) or
            a.hostname.removeprefix("www.") != b.hostname.removeprefix("www.")):
        return False
    digest = first.get("content_sha256")
    if digest and digest == second.get("content_sha256") and digest != EMPTY_CONTENT_SHA256:
        return True
    return equivalent_pages(first, second)


def _variant_preference(key, asset):
    scheme, host, _, _ = key
    title = (asset.get("site_identity") or {}).get("title", "")
    return (host != title, scheme != "http", host.startswith("www."), host)


def grouped_websites(assets):
    """Group proven website views while retaining checked paths as evidence."""
    groups = {}
    for asset in assets:
        if _eligible(asset):
            groups.setdefault(_group_key(asset), []).append(asset)
    for members in groups.values():
        members.sort(key=_preference)
    keys = list(groups)
    parent = {key: key for key in keys}

    def root(key):
        while parent[key] != key:
            parent[key] = parent[parent[key]]
            key = parent[key]
        return key

    def join(first, second):
        parent[root(second)] = root(first)

    for index, first_key in enumerate(keys):
        for second_key in keys[index + 1:]:
            if _same_site_views(groups[first_key][0], groups[second_key][0]):
                join(first_key, second_key)

    # An exact page titled with a hostname can reveal aliases that do not
    # redirect. The title and complete body must agree before they are folded.
    titled_pages = {}
    for key in keys:
        asset = groups[key][0]
        identity = asset.get("site_identity") or {}
        title = identity.get("title", "")
        digest = asset.get("content_sha256")
        if (asset.get("http_status") == 200 and digest and
                identity.get("captured_chars", 0) >= 512 and
                re.fullmatch(r"[a-z0-9][a-z0-9.-]*\.[a-z]{2,}", title)):
            marker = (title, digest, key[3])
            if marker in titled_pages:
                join(titled_pages[marker], key)
            else:
                titled_pages[marker] = key

    # A strongly identified Node.js error page joins a healthy protocol/www
    # view of the same host instead of creating an extra website row.
    for key in keys:
        asset = groups[key][0]
        if asset.get("http_status") == 200:
            continue
        for sibling in keys:
            healthy = groups[sibling][0]
            if (healthy.get("http_status") == 200 and
                    key[1].removeprefix("www.") == sibling[1].removeprefix("www.") and
                    key[3] == sibling[3]):
                join(sibling, key)
                break

    clusters = {}
    for key in keys:
        clusters.setdefault(root(key), []).append(key)
    display = []
    rank = {"NOT_ESTABLISHED": 0, "POSSIBLE": 1, "LIKELY": 2, "DETECTED": 3}
    for family in clusters.values():
        members = [asset for key in family for asset in groups[key]]
        healthy = [key for key in family if groups[key][0].get("http_status") == 200]
        if not healthy and not any(item.get("node") == "DETECTED" for item in members):
            continue
        variants = healthy or family[:1]
        preferred = min(variants, key=lambda key: _variant_preference(key, groups[key][0]))
        site_url = _site_origin(groups[preferred][0].get("final_url") or groups[preferred][0]["url"])
        primary = max(members, key=lambda item: (rank.get(item.get("node"), 0),
                                                  item.get("http_status") == 200,
                                                  not _preference(item)[1]))
        shown = dict(primary)
        shown["site_url"] = site_url
        shown["http_status"] = groups[preferred][0].get("http_status")
        shown["site_variants"] = [site_url] + sorted({
            _site_origin(groups[key][0].get("final_url") or groups[key][0]["url"])
            for key in variants
        } - {site_url})
        shown["checked_urls"] = sorted({url for item in members
                                        for url in (item["url"], item.get("final_url")) if url})
        shown["node"] = max((item.get("node", "NOT_ESTABLISHED") for item in members),
                            key=lambda value: rank.get(value, 0))
        shown["confidence"] = {"DETECTED": "high", "LIKELY": "medium",
                               "POSSIBLE": "low"}.get(shown["node"], "none")
        versions = {version for item in members for version in
                    ([item.get("version")] + list(item.get("reported_versions") or [])) if version}
        verdicts = {item.get("verdict") for item in members}
        if len(versions) > 1 or ("At risk" in verdicts and "Fixed version reported" in verdicts):
            shown["version"] = None if len(versions) > 1 else next(iter(versions))
            shown["verdict"] = "Unconfirmed"
            shown["verdict_reason"] = "Different pages reported conflicting Node.js versions or assessments."
            shown["site_conflict"] = True
        else:
            shown["version"] = next(iter(versions)) if versions else None
            shown["verdict"] = ("At risk" if "At risk" in verdicts else
                                "Fixed version reported" if shown["node"] == "DETECTED" and
                                "Fixed version reported" in verdicts else "Unconfirmed")
            source = next((item for item in members if item.get("verdict") == shown["verdict"]), None)
            shown["verdict_reason"] = source.get("verdict_reason", "") if source else ""
        shown["reported_versions"] = sorted(versions)
        shown["technologies"] = sorted({name for item in members for name in item.get("technologies", ())})
        technology_versions = {}
        for item in members:
            for name, version in item.get("technology_versions", {}).items():
                technology_versions.setdefault(name, set()).add(version)
        shown["technology_versions"] = {name: next(iter(values)) for name, values in technology_versions.items()
                                        if len(values) == 1}
        shown["brotli_response"] = any(item.get("brotli_response") for item in members)
        shown["proxy"] = sorted({name for item in members for name in item.get("proxy", ())})
        shown["evidence"] = []
        for item in members:
            for entry in item.get("evidence", ()):
                if entry not in shown["evidence"]:
                    shown["evidence"].append(entry)
        display.append(shown)
    return sorted(display, key=lambda item: item["site_url"])


def export_report(path, run, assets):
    path = Path(path)
    if path.suffix.lower() == ".csv":
        columns = ["url", "site_url", "final_url", "host", "connect_ip", "ips", "source",
                   "http_status", "node", "confidence", "version",
                   "reported_versions", "technologies", "technology_versions", "brotli_response", "verdict",
                   "verdict_reason", "proxy", "error", "evidence", "dns", "crawl"]
        with path.open("w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=columns)
            writer.writeheader()
            for asset in assets:
                row = {}
                for column in columns:
                    value = asset.get(column, "")
                    if isinstance(value, (dict, list)):
                        value = json.dumps(value, ensure_ascii=False)
                    if isinstance(value, str) and value.lstrip().startswith(("=", "+", "-", "@")):
                        value = "'" + value
                    row[column] = value
                writer.writerow(row)
    else:
        path.write_text(json.dumps({"schema": "node2shell-radar/1", "run": run,
                                    "assets": assets, "websites": grouped_websites(assets)},
                                   indent=2, ensure_ascii=False), encoding="utf-8")


RESULT_COLUMNS = ("Address", "HTTP", "Node.js", "Version", "Active check", "Result")


def export_visible_results(path, rows):
    """Save only the website rows currently shown in the results table."""
    path = Path(path)
    if path.suffix.lower() == ".csv":
        with path.open("w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=RESULT_COLUMNS)
            writer.writeheader()
            for result in rows:
                row = {}
                for column in RESULT_COLUMNS:
                    value = result.get(column, "")
                    if isinstance(value, str) and value.lstrip().startswith(("=", "+", "-", "@")):
                        value = "'" + value
                    row[column] = value
                writer.writerow(row)
    else:
        path.write_text(json.dumps({"results": rows}, indent=2, ensure_ascii=False), encoding="utf-8")
