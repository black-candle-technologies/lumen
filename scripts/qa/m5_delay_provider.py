#!/usr/bin/env python3
"""Disposable loopback OpenAI-compatible SSE provider for M5 delay acceptance."""

import argparse
import json
import time
from http.server import BaseHTTPRequestHandler, HTTPServer


MAX_REQUEST_BYTES = 1024 * 1024
FINAL_TEXT = "LUMEN_M5_DELAY_OK"


def create_server(port, delay_ms):
    if not 0 <= delay_ms <= 30000:
        raise ValueError("delay must be between 0 and 30000 ms")

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            if self.path != "/v1/chat/completions":
                self.send_error(404)
                return
            size = self.headers.get("Content-Length", "")
            if not size.isdecimal():
                self.send_error(400)
                return
            size = int(size)
            if size > MAX_REQUEST_BYTES:
                self.send_error(413)
                return
            try:
                request = json.loads(self.rfile.read(size))
            except (ValueError, UnicodeDecodeError):
                self.send_error(400)
                return
            if not isinstance(request, dict) or request.get("stream") is not True:
                self.send_error(400)
                return

            time.sleep(delay_ms / 1000)
            body = (
                "data: "
                + json.dumps({"choices": [{"index": 0, "delta": {"content": FINAL_TEXT}}]})
                + "\n\ndata: [DONE]\n\n"
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_):
            pass

    return HTTPServer(("127.0.0.1", port), Handler)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--delay-ms", required=True, type=int)
    args = parser.parse_args()
    with create_server(args.port, args.delay_ms) as server:
        print(f"ready loopback_port={server.server_port} delay_ms={args.delay_ms}", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
