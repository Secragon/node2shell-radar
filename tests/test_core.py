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
        grouped = grouped_websites(assets)
        self.assertEqual(len(grouped), 1)
        self.assertEqual(grouped[0]["site_variants"],
                         ["https://example.test/", "https://www.example.test/"])

    def test_redirected_subdomain_does_not_hide_matching_www_homepage(self):
        base = {"http_status": 200, "node": "LIKELY", "verdict": "Unconfirmed",
                "version": None, "connect_ip": None}
        assets = [{**base, "id": "apex", "url": "https://example.test/",
                   "final_url": "https://example.test/", "content_sha256": "homepage"},
                  {**base, "id": "support", "url": "https://support.example.test/",
                   "final_url": "https://www.example.test/support/", "content_sha256": "support-page"},
                  {**base, "id": "www", "url": "https://www.example.test/",
                   "final_url": "https://www.example.test/", "content_sha256": "homepage"}]
        grouped = grouped_websites(assets)
        self.assertEqual(len(grouped), 1)
        self.assertEqual(grouped[0]["site_variants"],
                         ["https://example.test/", "https://support.example.test/",
                          "https://www.example.test/"])

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

    def test_conflicting_versions_on_one_site_are_summarized(self):
        assets = [{"id": "a", "url": "http://example.test/", "final_url": "http://example.test/",
                   "http_status": 200, "node": "LIKELY", "verdict": "At risk", "version": "24.22.0",
                   "content_sha256": "same"},
                  {"id": "b", "url": "https://example.test/", "final_url": "https://example.test/",
                   "http_status": 200, "node": "LIKELY", "verdict": "Fixed version reported",
                   "version": "24.22.1", "content_sha256": "same"}]
        grouped = grouped_websites(assets)
        self.assertEqual(len(grouped), 1)
        self.assertEqual(grouped[0]["verdict"], "Unconfirmed")
        self.assertTrue(grouped[0]["site_conflict"])
        self.assertEqual(grouped[0]["reported_versions"], ["24.22.0", "24.22.1"])

    def test_http_upgrade_and_www_redirect_show_only_https_destination(self):
        assets = [{"id": "http", "url": "http://example.test/",
                   "final_url": "https://www.example.test/support/page", "http_status": 200,
                   "node": "LIKELY", "verdict": "Unconfirmed"},
                  {"id": "www", "url": "https://www.example.test/",
                   "final_url": "https://www.example.test/", "http_status": 200,
                   "node": "LIKELY", "verdict": "Unconfirmed"}]
        grouped = grouped_websites(assets)
        self.assertEqual(len(grouped), 1)
        self.assertEqual(grouped[0]["site_url"], "https://www.example.test/")
        self.assertEqual(grouped[0]["site_variants"],
                         ["https://www.example.test/", "http://example.test/"])

    def test_foreign_redirect_is_not_an_in_scope_site(self):
        asset = {"id": "alias", "url": "http://alias.example.test/",
                 "final_url": "https://foreign.test/", "site_url": "http://alias.example.test/",
                 "external_redirect": True, "http_status": 200, "node": "DETECTED",
                 "version": "24.22.0", "verdict": "At risk"}
        self.assertEqual(grouped_websites([asset]), [])

    def test_empty_200_and_weak_404_do_not_establish_sites(self):
        empty = fingerprint(response(url="https://empty.example.test/", text=""), ["example.test"])
        error = fingerprint(response(url="https://error.example.test/", status=404,
                                     headers={"x-powered-by": "Express", "content-type": "text/html"}),
                            ["example.test"])
        self.assertEqual(grouped_websites([
            {"id": "empty", "url": "https://empty.example.test/", **empty},
            {"id": "error", "url": "https://error.example.test/", **error},
        ]), [])

    def test_restricted_node_site_remains_a_candidate(self):
        for status in (401, 403):
            with self.subTest(status=status):
                url = "https://private.example.test/"
                asset = {"id": url, "url": url, **fingerprint(response(
                    url=url, status=status,
                    headers={"x-powered-by": "Express", "content-type": "text/html"},
                    text="<title>Sign in</title>"), ["example.test"])}
                grouped = grouped_websites([asset])
                self.assertEqual(len(grouped), 1)
                self.assertEqual(grouped[0]["node"], "LIKELY")
                self.assertEqual(grouped[0]["http_status"], status)

    def test_restricted_protocols_group_only_with_identical_responses(self):
        for status in (401, 403):
            with self.subTest(status=status):
                base = {"http_status": status, "node": "LIKELY", "verdict": "Unconfirmed",
                        "version": None, "connect_ip": None, "content_sha256": "same-login-page"}
                http = {**base, "id": "http", "url": "http://private.example.test/"}
                https = {**base, "id": "https", "url": "https://private.example.test/"}
                grouped = grouped_websites([http, https])
                self.assertEqual(len(grouped), 1)
                self.assertEqual(grouped[0]["site_variants"],
                                 ["http://private.example.test/", "https://private.example.test/"])
                different = {**https, "content_sha256": "different-login-page"}
                self.assertEqual(len(grouped_websites([http, different])), 2)

    def test_equivalent_dynamic_apex_and_www_pages_share_one_row(self):
        words = " ".join(f"topic{number}" for number in range(120))
        body = f"<title>Example service</title><p>{words}</p>"
        assets = []
        for host, text in (("example.test", body),
                           ("www.example.test", body.replace("topic45", "changed45"))):
            url = f"https://{host}/"
            assets.append({"id": url, "url": url,
                           **fingerprint(response(url=url, text=text,
                                                  headers={"content-type": "text/html",
                                                           "x-powered-by": "Express"}), ["example.test"])})
        grouped = grouped_websites(assets)
        self.assertEqual(len(grouped), 1)
        self.assertEqual(grouped[0]["site_variants"],
                         ["https://example.test/", "https://www.example.test/"])

    def test_hostname_titled_aliases_fold_under_named_site(self):
        body = "<title>about.example.test</title><p>" + "story " * 150 + "</p>"
        assets = []
        for host in ("about.example.test", "www.old.example.test"):
            url = f"https://{host}/"
            assets.append({"id": url, "url": url, "scope_roots": ["example.test"],
                           **fingerprint(response(url=url, text=body,
                                                  headers={"content-type": "text/html",
                                                           "x-powered-by": "Express"}), ["example.test"])})
        grouped = grouped_websites(assets)
        self.assertEqual(len(grouped), 1)
        self.assertEqual(grouped[0]["site_url"], "https://about.example.test/")
        self.assertEqual(len(grouped[0]["site_variants"]), 2)

    def test_identical_pages_from_different_input_scopes_stay_separate(self):
        body = "<title>app.first.test</title><p>" + "story " * 150 + "</p>"
        assets = []
        for host, scope in (("app.first.test", "first.test"),
                            ("app.second.test", "second.test")):
            url = f"https://{host}/"
            assets.append({"id": url, "url": url, "scope_roots": [scope],
                           **fingerprint(response(url=url, text=body,
                                                  headers={"content-type": "text/html",
                                                           "x-powered-by": "Express"}), [scope])})
        grouped = grouped_websites(assets)
        self.assertEqual([item["site_url"] for item in grouped],
                         ["https://app.first.test/", "https://app.second.test/"])


class EngineTests(unittest.TestCase):
    def test_wildcard_error_page_is_not_a_node_site_with_rotating_ip(self):
        async def fake_discover(options, network, control, emit):
            return [{"target": Target("account.example.test"), "source": {"active DNS"},
                     "ips": {"127.0.0.2"}, "dns": {"A": "OK"}, "wildcard": False,
                     "wildcard_root": "example.test", "wildcard_probe": "radar-random.example.test"}]

        requests = []
        def handler(request):
            requests.append(request)
            return httpx.Response(404, headers={"x-powered-by": "Express", "content-type": "text/html"},
                                  text="<title>Shared error page</title><p>Not found</p>")

        events = []
        options = ScanOptions([Target("example.test")], passive_dns=False, active_dns=False,
                              tls_names=False, words=[], interval=0)
        with patch("radar.engine.discover", fake_discover):
            asyncio.run(run_scan(options, Control(), events.append, httpx.MockTransport(handler)))
        checked = [event["asset"] for event in events if event["type"] == "asset"]
        self.assertEqual(len(checked), 2)
        self.assertTrue(all(asset.get("wildcard_http_match") for asset in checked))
        self.assertTrue(all(asset["node"] == "NOT_ESTABLISHED" for asset in checked))
        self.assertEqual(grouped_websites(checked), [])
        self.assertTrue(all(request.headers["user-agent"].startswith("Mozilla/5.0 (compatible; Node2Shell-Radar")
                            for request in requests))

    def test_wildcard_403_echoing_requested_host_is_not_a_site(self):
        async def fake_discover(options, network, control, emit):
            return [{"target": Target("account.example.test"), "source": {"active DNS"},
                     "ips": {"127.0.0.2"}, "dns": {"A": "OK"}, "wildcard": False,
                     "wildcard_root": "example.test", "wildcard_probe": "radar-random.example.test"}]

        def handler(request):
            host = request.url.host
            return httpx.Response(403, headers={"content-type": "text/html", "server": "Apache"},
                                  text=f"<title>Resource not found</title><h2>{host}</h2>"
                                       "<p>No site configured at this address.</p>")

        events = []
        options = ScanOptions([Target("example.test")], passive_dns=False, active_dns=False,
                              tls_names=False, words=[], interval=0)
        with patch("radar.engine.discover", fake_discover):
            asyncio.run(run_scan(options, Control(), events.append, httpx.MockTransport(handler)))
        checked = [event["asset"] for event in events if event["type"] == "asset"]
        self.assertEqual(len(checked), 2)
        self.assertTrue(all(asset.get("wildcard_http_match") for asset in checked))
        self.assertEqual(grouped_websites(checked), [])

    def test_wildcard_403_with_distinct_content_remains_a_site(self):
        baseline = fingerprint(response(url="http://radar-random.example.test/", status=403,
                                        text="<h2>radar-random.example.test</h2><p>No site configured</p>"),
                               ["example.test"])
        candidate = fingerprint(response(url="http://private.example.test/", status=403,
                                         text="<h2>private.example.test</h2><p>Private login</p>"),
                                ["example.test"])
        from radar.engine import wildcard_page_match
        self.assertFalse(wildcard_page_match(candidate, baseline))

    def test_unreachable_wildcard_port_is_not_repeated_for_each_name(self):
        async def fake_discover(options, network, control, emit):
            return [{"target": Target("account.example.test"), "source": {"active DNS"},
                     "ips": {"127.0.0.2"}, "dns": {"A": "OK"}, "wildcard": True,
                     "wildcard_root": "example.test", "wildcard_probe": "radar-random.example.test"}]
        async def unreachable(address, port, timeout):
            return False
        requested = []
        def handler(request):
            requested.append(str(request.url))
            return httpx.Response(404, text="No site")

        events = []
        options = ScanOptions([Target("example.test")], passive_dns=False, active_dns=False,
                              tls_names=False, words=[], interval=0)
        with patch("radar.engine.discover", fake_discover), patch("radar.engine.tcp_port_reachable", unreachable):
            asyncio.run(run_scan(options, Control(), events.append, httpx.MockTransport(handler)))
        self.assertEqual(len(requested), 2)  # One HTTP and one HTTPS random-name baseline.
        self.assertEqual([event["asset"]["node"] for event in events if event["type"] == "asset"],
                         ["NOT_ESTABLISHED", "NOT_ESTABLISHED"])
        finished = next(event for event in events if event["type"] == "finished")
        self.assertEqual(finished["coverage"]["wildcard_tcp_skipped"], 2)

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
