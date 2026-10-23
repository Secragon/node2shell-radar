import asyncio
import unittest
from unittest.mock import patch

import httpx

from radar.active import BR_INVALID_JSON, BR_VALID_JSON, check_brotli_json
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
        self.assertEqual(grouped_websites([asset])[0]["active_check"]["status"], "Parser observed")
        self.assertEqual([request.method for request in requests], ["GET", "OPTIONS", "OPTIONS", "OPTIONS"])

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


if __name__ == "__main__":
    unittest.main()
