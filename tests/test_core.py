import asyncio
import unittest
from unittest.mock import patch

import httpx

from radar.detection import fingerprint, next_script_urls, next_version_from_script
from radar.engine import Control, run_scan
from radar.models import ScanOptions, Target, assess_version, parse_targets
from radar.network import Response
from radar.storage import grouped_websites


def response(url="https://example.test/", headers=None, text="<html></html>", status=200):
    return Response(url, status, headers or {"content-type": "text/html"}, text, 20)


class VersionTests(unittest.TestCase):
    def test_fixed_boundaries(self):
        for older, fixed in (("22.23.3", "22.23.4"), ("24.22.0", "24.22.1"),
                             ("26.12.0", "26.12.1")):
            self.assertEqual(assess_version(older)[0], "At risk")
            self.assertEqual(assess_version(fixed)[0], "Fixed version reported")

    def test_unknown_and_vendor_builds_are_not_fixed(self):
        self.assertEqual(assess_version(None)[0], "Unconfirmed")
        self.assertEqual(assess_version("24.22.1-vendor")[0], "Unconfirmed")
        self.assertEqual(assess_version("20.19.0")[0], "Unconfirmed")

    def test_target_parser_rejects_credentials(self):
        with self.assertRaises(ValueError):
            parse_targets("https://user:password@example.test")


class DetectionTests(unittest.TestCase):
    def test_node_banner_reports_version(self):
        found = fingerprint(response(headers={"x-powered-by": "Node.js/v24.22.0"}), ["example.test"])
        self.assertEqual(found["node"], "DETECTED")
        self.assertEqual(found["version"], "24.22.0")
        self.assertEqual(found["verdict"], "At risk")

    def test_express_without_version_stays_unconfirmed(self):
        found = fingerprint(response(headers={"x-powered-by": "Express"}), ["example.test"])
        self.assertEqual(found["node"], "LIKELY")
        self.assertEqual(found["verdict"], "Unconfirmed")

    def test_next_assets_are_not_runtime_proof(self):
        found = fingerprint(response(text='<script src="/_next/static/chunks/app.js"></script>',
                                     headers={"content-type": "text/html"}), ["example.test"])
        self.assertEqual(found["node"], "POSSIBLE")
        self.assertEqual(found["verdict"], "Unconfirmed")

    def test_next_powered_by_header_is_likely_node(self):
        found = fingerprint(response(headers={"x-powered-by": "Next.js", "content-type": "text/html"},
                                     text='<script src="/_next/static/chunks/app.js"></script>'),
                            ["example.test"])
        self.assertEqual(found["node"], "LIKELY")
        self.assertEqual(found["confidence"], "medium")
        self.assertIn("Next.js", found["technologies"])
        self.assertEqual(found["verdict"], "Unconfirmed")

    def test_next_cache_header_alone_stays_possible(self):
        found = fingerprint(response(headers={"x-nextjs-cache": "HIT"}), ["example.test"])
        self.assertEqual(found["node"], "POSSIBLE")

    def test_next_version_is_a_framework_version(self):
        found = fingerprint(response(headers={"x-powered-by": "Next.js 16.3.3"}), ["example.test"])
        self.assertEqual(found["technology_versions"], {"Next.js": "16.3.3"})
        self.assertIsNone(found["version"])
        self.assertEqual(found["verdict"], "Unconfirmed")

    def test_next_client_bundle_version_and_same_origin_paths(self):
        html = ('<script src="/_next/static/chunks/runtime.js"></script>'
                '<script src="https://other.example.test/_next/static/chunks/foreign.js"></script>')
        urls = next_script_urls(response(text=html))
        self.assertEqual(urls, ["https://example.test/_next/static/chunks/runtime.js"])
        script = 'version:function(){return k}};let k="16.3.3";window.next={version:n.version}'
        self.assertEqual(next_version_from_script(script), "16.3.3")
        self.assertIsNone(next_version_from_script('let k="16.3.3";window.next={version:n.version}'))

    def test_brotli_response_is_not_vulnerability_proof(self):
        found = fingerprint(response(headers={"content-encoding": "br", "content-type": "text/html"}),
                            ["example.test"])
        self.assertTrue(found["brotli_response"])
        self.assertEqual(found["node"], "NOT_ESTABLISHED")
        self.assertEqual(found["verdict"], "Unconfirmed")


class GroupingTests(unittest.TestCase):
    def test_paths_on_same_site_are_one_result_with_paths_in_details(self):
        base = {"http_status": 200, "node": "LIKELY", "verdict": "Unconfirmed",
                "version": None, "connect_ip": None}
        assets = [{**base, "id": "home", "url": "https://example.test/",
                   "final_url": "https://example.test/", "content_sha256": "home"},
                  {**base, "id": "page", "url": "https://example.test/support/help",
                   "final_url": "https://example.test/support/help", "content_sha256": "other"}]
        groups = grouped_websites(assets)
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["site_url"], "https://example.test/")
        self.assertEqual(groups[0]["checked_urls"],
                         ["https://example.test/", "https://example.test/support/help"])

    def test_redirected_deep_path_displays_site_origin(self):
        asset = {"id": "input", "url": "http://example.test/",
                 "final_url": "https://example.test/support/help", "http_status": 200,
                 "node": "LIKELY", "verdict": "Unconfirmed", "version": None}
        group = grouped_websites([asset])[0]
        self.assertEqual(group["site_url"], "https://example.test/")
        self.assertIn(asset["final_url"], group["checked_urls"])

    def test_apex_and_www_with_different_content_stay_separate(self):
        base = {"http_status": 200, "node": "LIKELY", "verdict": "Unconfirmed",
                "version": None, "connect_ip": None}
        assets = [{**base, "id": "apex", "url": "https://example.test/",
                   "final_url": "https://example.test/", "content_sha256": "one"},
                  {**base, "id": "www-page", "url": "https://www.example.test/support/help",
                   "final_url": "https://www.example.test/support/help", "content_sha256": "two"}]
        groups = grouped_websites(assets)
        self.assertEqual([item["site_url"] for item in groups],
                         ["https://example.test/", "https://www.example.test/"])

    def test_identical_apex_and_www_homepages_fold_with_variants(self):
        base = {"http_status": 200, "node": "LIKELY", "verdict": "Unconfirmed",
                "version": None, "connect_ip": None, "content_sha256": "same"}
        assets = [{**base, "id": "apex", "url": "https://example.test/",
                   "final_url": "https://example.test/"},
                  {**base, "id": "www", "url": "https://www.example.test/",
                   "final_url": "https://www.example.test/"}]
        groups = grouped_websites(assets)
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["site_variants"],
                         ["https://example.test/", "https://www.example.test/"])

    def test_www_redirect_to_apex_is_one_result(self):
        base = {"http_status": 200, "node": "LIKELY", "verdict": "Unconfirmed",
                "version": None, "connect_ip": None}
        assets = [{**base, "id": "apex", "url": "https://example.test/",
                   "final_url": "https://example.test/"},
                  {**base, "id": "www", "url": "https://www.example.test/",
                   "final_url": "https://example.test/"}]
        self.assertEqual(len(grouped_websites(assets)), 1)

    def test_page_signal_upgrades_existing_site_candidate(self):
        base = {"http_status": 200, "verdict": "Unconfirmed", "version": None,
                "connect_ip": None}
        assets = [{**base, "id": "apex", "url": "https://example.test/",
                   "final_url": "https://example.test/", "node": "POSSIBLE"},
                  {**base, "id": "page", "url": "https://example.test/support/help",
                   "final_url": "https://example.test/support/help", "node": "LIKELY"}]
        groups = grouped_websites(assets)
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["node"], "LIKELY")
        self.assertEqual(groups[0]["site_url"], "https://example.test/")

    def test_http_and_https_equivalent_site_collapse(self):
        base = {"http_status": 200, "node": "LIKELY", "verdict": "Unconfirmed",
                "version": None, "content_sha256": "same", "connect_ip": None}
        assets = [{**base, "id": "http", "url": "http://example.test/",
                   "final_url": "http://example.test/"},
                  {**base, "id": "https", "url": "https://example.test/",
                   "final_url": "https://example.test/"}]
        groups = grouped_websites(assets)
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["site_url"], "http://example.test/")
        self.assertEqual(len(groups[0]["checked_urls"]), 2)

    def test_different_findings_stay_separate(self):
        assets = [{"id": "a", "url": "http://example.test/", "final_url": "http://example.test/",
                   "http_status": 200, "node": "LIKELY", "verdict": "At risk", "version": "24.22.0",
                   "content_sha256": "same"},
                  {"id": "b", "url": "https://example.test/", "final_url": "https://example.test/",
                   "http_status": 200, "node": "LIKELY", "verdict": "Fixed version reported",
                   "version": "24.22.1", "content_sha256": "same"}]
        self.assertEqual(len(grouped_websites(assets)), 2)


class EngineTests(unittest.TestCase):
    def test_engine_reads_next_client_version_without_node_version(self):
        async def fake_discover(options, network, control, emit):
            return [{"target": Target("example.test", "https://example.test/"),
                     "source": {"input"}, "ips": {"127.0.0.1"},
                     "dns": {"ips": ["127.0.0.1"]}}]

        requested = []

        def handler(request):
            requested.append(request.url.path)
            if request.url.path.startswith("/_next/static/"):
                return httpx.Response(200, text='version:function(){return k}};let k="16.3.3";'
                                                 'window.next={version:n.version}')
            return httpx.Response(200, headers={"x-powered-by": "Next.js", "content-type": "text/html"},
                                  text='<script src="/_next/static/chunks/runtime.js"></script>')

        events = []
        options = ScanOptions([Target("example.test", "https://example.test/")], passive_dns=False,
                              active_dns=False, tls_names=False, words=[], interval=0)
        with patch("radar.engine.discover", fake_discover):
            asyncio.run(run_scan(options, Control(), events.append, httpx.MockTransport(handler)))
        asset = next(event["asset"] for event in events if event["type"] == "asset")
        self.assertEqual(requested, ["/", "/_next/static/chunks/runtime.js"])
        self.assertEqual(asset["node"], "LIKELY")
        self.assertEqual(asset["technology_versions"], {"Next.js": "16.3.3"})
        self.assertIsNone(asset["version"])
        self.assertEqual(asset["verdict"], "Unconfirmed")

    def test_engine_reports_only_observed_node_signal(self):
        async def fake_discover(options, network, control, emit):
            return [{"target": Target("example.test"), "source": {"input"},
                     "ips": {"127.0.0.1"}, "dns": {"ips": ["127.0.0.1"]}}]

        def handler(request):
            if request.url.scheme == "http":
                return httpx.Response(301, headers={"location": "https://example.test/"})
            return httpx.Response(200, headers={"x-powered-by": "Express", "content-type": "text/html"},
                                  text="<html>hello</html>")

        events = []
        options = ScanOptions([Target("example.test")], passive_dns=False, active_dns=False,
                              tls_names=False, words=[], interval=0)
        with patch("radar.engine.discover", fake_discover):
            asyncio.run(run_scan(options, Control(), events.append, httpx.MockTransport(handler)))
        assets = [event["asset"] for event in events if event["type"] == "asset"]
        self.assertEqual(len(assets), 2)
        self.assertTrue(all(asset["node"] == "LIKELY" for asset in assets))
        self.assertEqual(len(grouped_websites(assets)), 1)
        self.assertEqual([event["status"] for event in events if event["type"] == "finished"],
                         ["COMPLETED"])
