import asyncio
import unittest
from unittest.mock import patch

import httpx

from radar.active import (BR_INVALID_JSON, BR_VALID_JSON, STRAPI_LOGIN_BR,
                          STRAPI_LOGIN_JSON, check_active_paths, check_brotli_json,
                          check_strapi_login)
from radar.engine import Control, run_scan
from radar.models import ScanOptions, Target
from radar.network import Network
from radar.storage import grouped_websites


class ActiveProbeTests(unittest.TestCase):
    def test_complete_brotli_json_parser_is_reported_without_redirects(self):
        requests = []

        def handler(request):
            requests.append(request)
            if request.headers.get("content-encoding") == "br":
                return httpx.Response(204 if request.content == BR_VALID_JSON else 400)
            return httpx.Response(400)

        async def check():
            options = ScanOptions([Target("example.test")], interval=0)
            network = Network(options, Control(), httpx.MockTransport(handler))
            try:
                return await check_brotli_json(network, "https://example.test/")
            finally:
                await network.close()

        result = asyncio.run(check())
        self.assertEqual(result["status"], "Parser observed")
        self.assertEqual(result["http_statuses"], [400, 204, 400])
        self.assertEqual([request.method for request in requests], ["OPTIONS"] * 3)
        self.assertEqual([request.content for request in requests],
                         [b"{", BR_VALID_JSON, BR_INVALID_JSON])
        self.assertTrue(all(request.url.host == "example.test" for request in requests))

    def test_rejection_and_missing_parser_are_not_positive(self):
        async def check(handler):
            options = ScanOptions([Target("example.test")], interval=0)
            network = Network(options, Control(), httpx.MockTransport(handler))
            try:
                return await check_brotli_json(network, "https://example.test/")
            finally:
                await network.close()

        rejected = asyncio.run(check(lambda request: httpx.Response(
            415 if request.headers.get("content-encoding") == "br" else 400)))
        self.assertEqual(rejected["status"], "Rejected here")
        missing = asyncio.run(check(lambda request: httpx.Response(404)))
        self.assertEqual(missing["status"], "Inconclusive")
        self.assertEqual(missing["http_statuses"], [404])

    def test_engine_runs_probe_only_for_in_scope_candidate_and_preserves_verdict(self):
        async def fake_discover(options, network, control, emit):
            return [{"target": Target("example.test", "https://example.test/"),
                     "source": {"input"}, "ips": {"127.0.0.1"},
                     "dns": {"ips": ["127.0.0.1"]}}]

        requests = []

        def handler(request):
            requests.append(request)
            if request.method == "GET":
                return httpx.Response(200, headers={"x-powered-by": "Node.js/v24.22.0"},
                                      text="<html>Candidate</html>")
            if request.headers.get("content-encoding") == "br":
                return httpx.Response(204 if request.content == BR_VALID_JSON else 400)
            return httpx.Response(400)

        events = []
        options = ScanOptions([Target("example.test", "https://example.test/")],
                              passive_dns=False, active_dns=False, tls_names=False,
                              words=[], interval=0, active_check=True)
        with patch("radar.engine.discover", fake_discover):
            asyncio.run(run_scan(options, Control(), events.append, httpx.MockTransport(handler)))
        asset = next(event["asset"] for event in events if event["type"] == "asset" and
                     event["asset"].get("node") != "PENDING")
        self.assertEqual(asset["verdict"], "At risk")
        self.assertEqual(asset["active_check"]["status"], "Parser observed")
        grouped = grouped_websites([asset])[0]
        self.assertEqual(grouped["active_check"]["status"], "Parser observed")
        self.assertEqual(grouped["decoder_patch_status"], "Unverified remotely")
        self.assertEqual([check["name"] for check in grouped["active_checks"]],
                         ["JSON parser route", "Strapi login"])
        self.assertEqual([request.method for request in requests],
                         ["GET", "OPTIONS", "OPTIONS", "OPTIONS", "POST"])

    def test_strapi_paired_login_confirms_parser_only_for_matching_error(self):
        requests = []
        login_error = ('{"data":null,"error":{"status":400,"name":"ValidationError",'
                       '"message":"Invalid identifier or password","details":{}}}')

        def handler(request):
            requests.append(request)
            return httpx.Response(400, text=login_error)

        async def check():
            options = ScanOptions([Target("example.test")], interval=0)
            network = Network(options, Control(), httpx.MockTransport(handler))
            try:
                return await check_strapi_login(network, "https://example.test/panel")
            finally:
                await network.close()

        result = asyncio.run(check())
        self.assertEqual(result["status"], "Parser observed")
        self.assertEqual(result["http_statuses"], [400, 400])
        self.assertEqual([request.method for request in requests], ["POST", "POST"])
        self.assertEqual([str(request.url) for request in requests],
                         ["https://example.test/api/auth/local"] * 2)
        self.assertEqual([request.content for request in requests],
                         [STRAPI_LOGIN_JSON, STRAPI_LOGIN_BR])
        self.assertNotEqual(STRAPI_LOGIN_JSON, STRAPI_LOGIN_BR)

    def test_strapi_rejection_and_unknown_route_are_not_positive(self):
        login_error = ('{"data":null,"error":{"status":400,"name":"ValidationError",'
                       '"message":"Invalid identifier or password","details":{}}}')

        async def check(handler):
            requests = []
            def tracked(request):
                requests.append(request)
                return handler(request)
            network = Network(ScanOptions([Target("example.test")], interval=0),
                              Control(), httpx.MockTransport(tracked))
            try:
                result = await check_strapi_login(network, "https://example.test/")
                return result, requests
            finally:
                await network.close()

        blocked, requests = asyncio.run(check(lambda request: httpx.Response(
            415, text="Encoding not supported") if request.headers.get("content-encoding") else
            httpx.Response(400, text=login_error)))
        self.assertEqual(blocked["status"], "Rejected here")
        self.assertEqual(len(requests), 2)
        unknown, requests = asyncio.run(check(lambda request: httpx.Response(404)))
        self.assertEqual(unknown["status"], "Inconclusive")
        self.assertEqual(len(requests), 1)

    def test_combined_result_uses_strongest_route_and_version_context(self):
        login_error = ('{"data":null,"error":{"status":400,"name":"ValidationError",'
                       '"message":"Invalid identifier or password","details":{}}}')

        def handler(request):
            if request.method == "OPTIONS":
                return httpx.Response(404)
            return httpx.Response(400, text=login_error)

        async def check():
            network = Network(ScanOptions([Target("example.test")], interval=0),
                              Control(), httpx.MockTransport(handler))
            try:
                return await check_active_paths(network, "https://example.test/",
                                                verdict="At risk")
            finally:
                await network.close()

        result = asyncio.run(check())
        self.assertEqual(result["status"], "Parser observed")
        self.assertEqual(result["decoder_patch_status"], "Unverified remotely")
        self.assertEqual([item["status"] for item in result["checks"]],
                         ["Inconclusive", "Parser observed"])
        self.assertIn("pre-fix", result["assessment"])

    def test_external_redirect_is_not_probed(self):
        async def fake_discover(options, network, control, emit):
            return [{"target": Target("example.test", "https://example.test/"),
                     "source": {"input"}, "ips": {"127.0.0.1"},
                     "dns": {"ips": ["127.0.0.1"]}}]

        requests = []

        def handler(request):
            requests.append(request)
            if request.url.host == "example.test":
                return httpx.Response(302, headers={"location": "https://outside.test/"})
            return httpx.Response(200, headers={"x-powered-by": "Node.js/v24.22.0"},
                                  text="<html>Outside</html>")

        events = []
        options = ScanOptions([Target("example.test", "https://example.test/")],
                              passive_dns=False, active_dns=False, tls_names=False,
                              words=[], interval=0, active_check=True)
        with patch("radar.engine.discover", fake_discover):
            asyncio.run(run_scan(options, Control(), events.append, httpx.MockTransport(handler)))
        asset = next(event["asset"] for event in events if event["type"] == "asset" and
                     event["asset"].get("node") != "PENDING")
        self.assertTrue(asset["external_redirect"])
        self.assertEqual(asset["active_check"]["status"], "Skipped")
        self.assertTrue(all(request.method == "GET" for request in requests))

    def test_unselected_active_check_makes_no_post_or_options_requests(self):
        async def fake_discover(options, network, control, emit):
            return [{"target": Target("example.test", "https://example.test/"),
                     "source": {"input"}, "ips": {"127.0.0.1"},
                     "dns": {"ips": ["127.0.0.1"]}}]

        requests = []
        def handler(request):
            requests.append(request)
            return httpx.Response(200, headers={"x-powered-by": "Node.js/v24.22.0"},
                                  text="<html>Candidate</html>")

        events = []
        options = ScanOptions([Target("example.test", "https://example.test/")],
                              passive_dns=False, active_dns=False, tls_names=False,
                              words=[], interval=0, active_check=False)
        with patch("radar.engine.discover", fake_discover):
            asyncio.run(run_scan(options, Control(), events.append, httpx.MockTransport(handler)))
        self.assertEqual([request.method for request in requests], ["GET"])


if __name__ == "__main__":
    unittest.main()
