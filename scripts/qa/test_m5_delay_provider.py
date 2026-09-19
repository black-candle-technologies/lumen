"""Wire and timing checks for the disposable M5 delayed-model fixture."""

import importlib
import http.client
import json
import threading
import time
import unittest
from urllib.request import Request, urlopen
from urllib.error import HTTPError


class DelayProviderTests(unittest.TestCase):
    def test_refuses_out_of_range_delay(self):
        provider = importlib.import_module("m5_delay_provider")
        for delay_ms in (-1, 30001):
            with self.subTest(delay_ms=delay_ms):
                with self.assertRaises(ValueError):
                    with provider.create_server(port=0, delay_ms=delay_ms):
                        pass

    def start_server(self, delay_ms=0):
        provider = importlib.import_module("m5_delay_provider")
        server = provider.create_server(port=0, delay_ms=delay_ms)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 2)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server

    def test_streams_final_text_after_configured_delay(self):
        server = self.start_server(delay_ms=80)

        payload = json.dumps({
            "model": "qa-delay",
            "messages": [{"role": "user", "content": "Reply with marker"}],
            "stream": True,
        }).encode()
        request = Request(
            f"http://127.0.0.1:{server.server_port}/v1/chat/completions",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        started = time.perf_counter()
        with urlopen(request, timeout=3) as response:
            self.assertEqual(response.status, 200)
            self.assertEqual(response.headers["Content-Type"], "text/event-stream")
            body = response.read().decode()
        self.assertGreaterEqual(time.perf_counter() - started, 0.07)
        frames = [line.removeprefix("data: ") for line in body.splitlines() if line.startswith("data: ")]
        self.assertEqual(len(frames), 2)
        self.assertEqual(json.loads(frames[0]), {
            "choices": [{"index": 0, "delta": {"content": "LUMEN_M5_DELAY_OK"}}]
        })
        self.assertEqual(frames[1], "[DONE]")

    def test_rejects_non_stream_request(self):
        server = self.start_server()
        request = Request(
            f"http://127.0.0.1:{server.server_port}/v1/chat/completions",
            data=json.dumps({"model": "qa-delay", "messages": [], "stream": False}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with self.assertRaises(HTTPError) as failure:
            urlopen(request, timeout=3)
        self.assertEqual(failure.exception.code, 400)
        failure.exception.close()

    def test_rejects_oversized_request_before_parsing(self):
        server = self.start_server()
        connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
        self.addCleanup(connection.close)
        connection.request(
            "POST", "/v1/chat/completions", body=b"",
            headers={"Content-Length": str(1024 * 1024 + 1)},
        )
        response = connection.getresponse()
        self.assertEqual(response.status, 413)
        response.read()


if __name__ == "__main__":
    unittest.main()
