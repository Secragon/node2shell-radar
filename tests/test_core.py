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


def assessed_assets(events):
    return [event["asset"] for event in events
            if event["type"] == "asset" and event["asset"].get("node") != "PENDING"]


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

    def test_strapi_header_is_node_candidate_without_claiming_runtime_version(self):
        found = fingerprint(response(headers={"x-powered-by": "Strapi"}), ["example.test"])
        self.assertEqual(found["node"], "LIKELY")
        self.assertIn("Strapi", found["technologies"])
        self.assertIsNone(found["version"])

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
                '<script src="/portal/_next/static/chunks/app.js"></script>'
                '<script src="https://other.example.test/_next/static/chunks/foreign.js"></script>')
        urls = next_script_urls(response(text=html))
        self.assertEqual(urls, ["https://example.test/_next/static/chunks/runtime.js",
                                "https://example.test/portal/_next/static/chunks/app.js"])
        script = 'version:function(){return k}};let k="16.3.3";window.next={version:n.version}'
        self.assertEqual(next_version_from_script(script), "16.3.3")
        self.assertIsNone(next_version_from_script('let k="16.3.3";window.next={version:n.version}'))

    def test_modern_framework_html_markers_are_candidates_only(self):
        cases = (
            ("Next.js", '<script>self.__next_f.push([1,"payload"])</script>'),
            ("Nuxt", '<script id="__NUXT_DATA__" type="application/json">[]</script>'),
            ("Remix", '<script>window.__remixContext={};</script>'),
            ("React Router", '<script>window.__reactRouterContext={};</script>'),
            ("SvelteKit", '<a href="/about" data-sveltekit-preload-data="hover">About</a>'),
            ("Astro", '<astro-island component-url="/widget.js"></astro-island>'),
            ("Gatsby", '<div id="___gatsby"></div>'),
            ("Meteor", '<link class="__meteor-css__" rel="stylesheet" href="/main.css">'),
            ("RedwoodJS", '<div id="redwood-app"></div>'),
        )
        for framework, html in cases:
            with self.subTest(framework=framework):
                found = fingerprint(response(text=html), ["example.test"])
                self.assertEqual(found["node"], "POSSIBLE")
                self.assertIn(framework, found["technologies"])
                self.assertIsNone(found["version"])
                self.assertEqual(found["verdict"], "Unconfirmed")

    def test_framework_version_from_generator_is_not_node_version(self):
        found = fingerprint(response(text='<meta name="generator" content="Nuxt 4.1.2">'),
                            ["example.test"])
        self.assertEqual(found["node"], "POSSIBLE")
        self.assertEqual(found["technology_versions"], {"Nuxt": "4.1.2"})
        self.assertIsNone(found["version"])

    def test_framework_name_in_visible_documentation_is_not_a_marker(self):
        found = fingerprint(response(text='<pre>self.__next_f.push; __NUXT_DATA__; '
                                          'data-sveltekit-preload-data; __reactRouterContext; '
                                          'astro-island; ___gatsby</pre>'), ["example.test"])
        self.assertEqual(found["node"], "NOT_ESTABLISHED")

    def test_specific_backend_cookies_are_candidates_without_exposing_values(self):
        cases = (("koa:sess", "Koa"), ("sails.sid", "Sails.js"),
                 ("adonis-session", "AdonisJS"))
        for cookie, framework in cases:
            with self.subTest(cookie=cookie):
                found = fingerprint(response(headers={"set-cookie": f"{cookie}=secret-token; Path=/"}),
                                    ["example.test"])
                self.assertEqual(found["node"], "LIKELY")
                self.assertIn(framework, found["technologies"])
                self.assertNotIn("secret-token", repr(found["evidence"]))

    def test_multi_runtime_framework_does_not_imply_node_runtime(self):
        found = fingerprint(response(headers={"x-powered-by": "Hono"}), ["example.test"])
        self.assertEqual(found["node"], "POSSIBLE")
        self.assertIn("Hono", found["technologies"])
        self.assertIsNone(found["version"])

    def test_explicit_nest_header_is_a_node_candidate(self):
        found = fingerprint(response(headers={"x-powered-by": "Nest"}), ["example.test"])
        self.assertEqual(found["node"], "LIKELY")
        self.assertIn("NestJS", found["technologies"])

    def test_frontend_library_alone_does_not_imply_node(self):
        found = fingerprint(response(text='<div id="app" ng-version="20.0.0" q:version="1.0.0">'
                                          '<script src="/react.js"></script>'
                                          '<script>_$HY.init("root")</script></div>'), ["example.test"])
        self.assertEqual(found["node"], "NOT_ESTABLISHED")

    def test_astro_generator_version_is_not_a_node_version(self):
        found = fingerprint(response(text='<meta name="generator" content="Astro v5.2.1">'),
                            ["example.test"])
        self.assertEqual(found["technology_versions"], {"Astro": "5.2.1"})
        self.assertIsNone(found["version"])
        self.assertEqual(found["node"], "POSSIBLE")

    def test_framework_header_version_is_not_node_version(self):
        found = fingerprint(response(headers={"x-powered-by": "Nuxt 4.1.2"}), ["example.test"])
        self.assertEqual(found["node"], "LIKELY")
        self.assertEqual(found["technology_versions"], {"Nuxt": "4.1.2"})
        self.assertIsNone(found["version"])

    def test_brotli_response_is_not_vulnerability_proof(self):
        found = fingerprint(response(headers={"content-encoding": "br", "content-type": "text/html"}),
                            ["example.test"])
        self.assertTrue(found["brotli_response"])
        self.assertEqual(found["node"], "NOT_ESTABLISHED")
        self.assertEqual(found["verdict"], "Unconfirmed")


class GroupingTests(unittest.TestCase):
    def test_site_rows_follow_asset_arrival_order(self):
        assets = [{"id": host, "url": f"https://{host}/", "http_status": 200,
                   "node": "LIKELY", "verdict": "Unconfirmed",
                   "content_sha256": host}
                  for host in ("z.example.test", "a.example.test")]
        self.assertEqual([site["site_url"] for site in grouped_websites(assets)],
                         ["https://z.example.test/", "https://a.example.test/"])

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
        self.assertEqual(groups[0]["site_variants"],
                         ["http://example.test/", "https://example.test/"])

    def test_http_upgrade_shows_only_https_destination(self):
        base = {"http_status": 200, "node": "LIKELY", "verdict": "Unconfirmed",
                "version": None, "content_sha256": "same", "connect_ip": None}
        assets = [{**base, "id": "http", "url": "http://example.test/",
                   "final_url": "https://example.test/"},
                  {**base, "id": "https", "url": "https://example.test/",
                   "final_url": "https://example.test/"}]
        groups = grouped_websites(assets)
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["site_variants"], ["https://example.test/"])
        self.assertEqual(groups[0]["checked_urls"],
                         ["http://example.test/", "https://example.test/"])

    def test_http_and_https_different_sites_with_shared_layout_stay_separate(self):
        shared = " ".join(f"topic{number}" for number in range(120))
        assets = []
        for scheme, title, detail in (("http", "Internal admin portal", "Administration"),
                                      ("https", "Public customer portal", "Shopping")):
            url = f"{scheme}://example.test/"
            body = f"<html><title>{title}</title><p>{shared}</p><p>{detail}</p></html>"
            assets.append({"id": url, "url": url, **fingerprint(response(
                url=url, text=body, headers={"content-type": "text/html",
                                              "x-powered-by": "Express"}), ["example.test"])})
        groups = grouped_websites(assets)
        self.assertEqual([group["site_url"] for group in groups],
                         ["http://example.test/", "https://example.test/"])
        self.assertEqual([group["site_variants"] for group in groups],
                         [["http://example.test/"], ["https://example.test/"]])

    def test_distinct_canonical_paths_do_not_merge_shared_layouts(self):
        shared = " ".join(f"topic{number}" for number in range(120))
        assets = []
        for scheme, title, path in (("http", "Internal admin portal", "admin"),
                                    ("https", "Public customer portal", "shop")):
            url = f"{scheme}://example.test/"
            body = (f'<title>{title}</title><link rel="canonical" '
                    f'href="https://example.test/{path}"><p>{shared}</p>')
            asset = {"id": url, "url": url, **fingerprint(response(
                url=url, text=body, headers={"content-type": "text/html",
                                             "x-powered-by": "Express"}), ["example.test"])}
            assets.append(asset)
        self.assertEqual([asset["site_identity"]["canonical"] for asset in assets],
                         ["https://example.test/admin", "https://example.test/shop"])
        self.assertEqual(len(grouped_websites(assets)), 2)

    def test_short_identical_pages_do_not_prove_two_protocols_are_one_site(self):
        assets = []
        for scheme in ("http", "https"):
            url = f"{scheme}://example.test/"
            assets.append({"id": url, "url": url, **fingerprint(response(
                url=url, text="abc", headers={"content-type": "text/html",
                                               "x-powered-by": "Express"}), ["example.test"])})
        self.assertEqual(len(grouped_websites(assets)), 2)

    def test_restricted_and_healthy_protocol_views_remain_separate(self):
        assets = [{"id": scheme, "url": f"{scheme}://example.test/",
                   "http_status": status, "node": "LIKELY", "verdict": "Unconfirmed",
                   "content_sha256": digest}
                  for scheme, status, digest in (("http", 401, "login"),
                                                 ("https", 200, "home"))]
        self.assertEqual(len(grouped_websites(assets)), 2)

    def test_server_error_joins_healthy_view_but_restricted_view_does_not(self):
        assets = [{"id": "healthy", "url": "https://example.test/", "http_status": 200,
                   "node": "LIKELY", "verdict": "Unconfirmed", "content_sha256": "home"},
                  {"id": "error", "url": "http://example.test/", "http_status": 503,
                   "node": "DETECTED", "verdict": "Unconfirmed", "content_sha256": "error"}]
        grouped = grouped_websites(assets)
        self.assertEqual(len(grouped), 1)
        self.assertEqual(grouped[0]["site_url"], "https://example.test/")
        self.assertEqual(grouped[0]["node"], "DETECTED")

    def test_two_server_error_protocols_are_one_host_result(self):
        assets = [{"id": scheme, "url": f"{scheme}://example.test/",
                   "http_status": 503, "node": "DETECTED", "verdict": "Unconfirmed",
                   "content_sha256": digest}
                  for scheme, digest in (("http", "first-error"), ("https", "second-error"))]
        self.assertEqual(len(grouped_websites(assets)), 1)

    def test_unidentified_protocol_view_does_not_add_other_site_row(self):
        assets = [{"id": "http", "url": "http://example.test/", "http_status": 200,
                   "node": "NOT_ESTABLISHED", "verdict": "Unconfirmed",
                   "content_sha256": "public"},
                  {"id": "https", "url": "https://example.test/", "http_status": 200,
                   "node": "LIKELY", "verdict": "Unconfirmed",
                   "content_sha256": "different-app"}]
        grouped = grouped_websites(assets)
        self.assertEqual(len(grouped), 1)
        self.assertEqual(grouped[0]["site_url"], "https://example.test/")

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
    def test_unresolved_dns_candidate_is_saved_without_http_request(self):
        async def fake_discover(options, network, control, emit):
            return [{"target": Target("missing.example.test"), "source": {"public source"},
                     "ips": set(), "dns": {"status": "NXDOMAIN"},
                     "scope_roots": {"example.test"}}]

        requests = []
        def handler(request):
            requests.append(request)
            return httpx.Response(200)

        events = []
        options = ScanOptions([Target("example.test")], passive_dns=False, active_dns=False,
                              tls_names=False, words=[], interval=0)
        with patch("radar.engine.discover", fake_discover):
            asyncio.run(run_scan(options, Control(), events.append, httpx.MockTransport(handler)))
        assets = assessed_assets(events)
        self.assertEqual({asset["url"] for asset in assets},
                         {"https://missing.example.test/", "http://missing.example.test/"})
        self.assertEqual(len([event for event in events if event["type"] == "asset" and
                              event["asset"]["node"] == "PENDING"]), 2)
        self.assertTrue(all(asset["node"] == "NOT_ESTABLISHED" and asset["dns"]["status"] == "NXDOMAIN"
                            for asset in assets))
        self.assertEqual(requests, [])
        self.assertEqual(grouped_websites(assets), [])
        self.assertEqual(next(event for event in events if event["type"] == "finished")
                         ["coverage"]["dns_unresolved"], 1)

    def test_crawled_page_is_its_own_asset_and_upgrades_one_site(self):
        async def fake_discover(options, network, control, emit):
            return [{"target": Target("example.test", "https://example.test/"),
                     "source": {"input"}, "ips": {"127.0.0.1"},
                     "dns": {"ips": ["127.0.0.1"]}, "scope_roots": {"example.test"}}]

        def handler(request):
            if request.url.path == "/":
                return httpx.Response(200, headers={"content-type": "text/html"},
                                      text='<a href="/hidden">Hidden page</a>')
            if request.url.path == "/hidden":
                return httpx.Response(200, headers={"content-type": "text/html",
                                                    "x-powered-by": "Node.js/v24.22.0"},
                                      text="<title>Hidden service</title>")
            return httpx.Response(404, headers={"content-type": "text/plain"}, text="Not found")

        events = []
        options = ScanOptions([Target("example.test", "https://example.test/")],
                              passive_dns=False, active_dns=False, tls_names=False,
                              words=[], interval=0, crawl=True)
        with patch("radar.engine.discover", fake_discover):
            asyncio.run(run_scan(options, Control(), events.append, httpx.MockTransport(handler)))
        assets = {asset["url"]: asset for asset in assessed_assets(events)}
        self.assertIn("https://example.test/hidden", assets)
        self.assertEqual(assets["https://example.test/hidden"]["source"], ["application crawl"])
        self.assertEqual(assets["https://example.test/"]["node"], "NOT_ESTABLISHED")
        self.assertEqual(assets["https://example.test/hidden"]["node"], "DETECTED")
        grouped = grouped_websites(assets.values())
        self.assertEqual(len(grouped), 1)
        self.assertEqual(grouped[0]["site_url"], "https://example.test/")
        self.assertEqual(grouped[0]["node"], "DETECTED")
        self.assertIn("https://example.test/hidden", grouped[0]["checked_urls"])

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
        checked = assessed_assets(events)
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
        checked = assessed_assets(events)
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
        self.assertEqual([asset["node"] for asset in assessed_assets(events)],
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
            if "/_next/static/" in request.url.path:
                return httpx.Response(200, text='version:function(){return k}};let k="16.3.3";'
                                                 'window.next={version:n.version}')
            return httpx.Response(200, headers={"x-powered-by": "Next.js", "content-type": "text/html"},
                                  text='<script src="/portal/_next/static/chunks/runtime.js"></script>')

        events = []
        options = ScanOptions([Target("example.test", "https://example.test/")], passive_dns=False,
                              active_dns=False, tls_names=False, words=[], interval=0)
        with patch("radar.engine.discover", fake_discover):
            asyncio.run(run_scan(options, Control(), events.append, httpx.MockTransport(handler)))
        asset = assessed_assets(events)[0]
        self.assertEqual(requested, ["/", "/portal/_next/static/chunks/runtime.js"])
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
        assets = assessed_assets(events)
        self.assertEqual(len(assets), 2)
        self.assertTrue(all(asset["node"] == "LIKELY" for asset in assets))
        self.assertEqual(len(grouped_websites(assets)), 1)
        self.assertEqual([event["status"] for event in events if event["type"] == "finished"],
                         ["COMPLETED"])
