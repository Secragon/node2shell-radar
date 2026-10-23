"""Local sessions, exports and website presentation grouping."""

import csv
import json
from pathlib import Path
import sqlite3
from urllib.parse import urlsplit, urlunsplit


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


def _group_key(asset):
    final = asset.get("final_url") or asset["url"]
    parsed = urlsplit(final)
    host = (parsed.hostname or "").lower()
    port = parsed.port
    backend = asset.get("connect_ip")
    verdict = asset.get("verdict")
    version = asset.get("version")
    # Results represent websites. Paths checked on the same backend with the
    # same version assessment are evidence for one result, even when one path
    # exposes stronger framework clues than another.
    return (host, port if port not in (None, 80, 443) else None, backend,
            verdict, version)


def _site_origin(url):
    parsed = urlsplit(url)
    return urlunsplit((parsed.scheme, parsed.netloc, "/", "", ""))


def grouped_websites(assets):
    groups = {}
    for asset in assets:
        if not asset.get("http_status"):
            continue
        groups.setdefault(_group_key(asset), []).append(asset)
    # Apex and www may serve different applications. Fold them only when a
    # redirect reaches the same final host (handled above), or when complete
    # responses for the same path have identical content and findings.
    parents = {key: key for key in groups}

    def root(key):
        while parents[key] != key:
            parents[key] = parents[parents[key]]
            key = parents[key]
        return key

    identical = {}
    for key, members in groups.items():
        for item in members:
            digest = item.get("content_sha256")
            if item.get("http_status") != 200 or not digest or item.get("detection_partial"):
                continue
            final = urlsplit(item.get("final_url") or item["url"])
            host = (final.hostname or "").lower()
            if not host:
                continue
            signature = (final.scheme, host.removeprefix("www."),
                         final.port or (443 if final.scheme == "https" else 80),
                         final.path or "/", final.query, digest, item.get("connect_ip"),
                         item.get("node"), item.get("verdict"), item.get("version"),
                         tuple(item.get("proxy") or ()))
            other = identical.setdefault(signature, key)
            if other != key:
                parents[root(key)] = root(other)
    merged = {}
    for key, members in groups.items():
        merged.setdefault(root(key), []).extend(members)
    groups = merged
    display = []
    for members in groups.values():
        redirected_to_https = any(
            item["url"].startswith("http://") and
            (item.get("final_url") or "").startswith("https://") for item in members
        )
        preferred_scheme = "https" if redirected_to_https else "http"
        presentation = sorted(members, key=lambda item: (
            not item["url"].startswith(preferred_scheme + "://"),
            (urlsplit(item.get("final_url") or item["url"]).hostname or "").startswith("www."),
            len(urlsplit(item.get("final_url") or item["url"]).path), item["url"]
        ))[0]
        rank = {"NOT_ESTABLISHED": 0, "POSSIBLE": 1, "LIKELY": 2, "DETECTED": 3}
        primary = max(members, key=lambda item: (rank.get(item.get("node"), 0),
                                                  item.get("http_status") == 200))
        shown = dict(primary)
        shown["checked_urls"] = sorted({url for item in members
                                        for url in (item["url"], item.get("final_url")) if url})
        shown["site_variants"] = sorted({_site_origin(url) for url in shown["checked_urls"]})
        shown["technologies"] = sorted({name for item in members for name in item.get("technologies", ())})
        technology_versions = {}
        for item in members:
            for name, version in item.get("technology_versions", {}).items():
                technology_versions.setdefault(name, set()).add(version)
        shown["technology_versions"] = {name: next(iter(versions)) for name, versions in technology_versions.items()
                                        if len(versions) == 1}
        shown["evidence"] = []
        for item in members:
            for entry in item.get("evidence", ()):
                if entry not in shown["evidence"]:
                    shown["evidence"].append(entry)
        if redirected_to_https:
            shown["site_url"] = _site_origin(presentation.get("final_url") or presentation["url"])
        else:
            shown["site_url"] = _site_origin(presentation["url"])
        if shown["site_url"] not in shown["site_variants"]:
            shown["site_variants"].insert(0, shown["site_url"])
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
