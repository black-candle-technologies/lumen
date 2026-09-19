#!/usr/bin/env python3
"""Inspect one run across every workspace audit page without hiding HTTP errors."""

import argparse
import http.client
import ipaddress
import json
import os
import sys
import uuid
from urllib.parse import urlencode, urlsplit


SUCCESS_BYTES = 32 * 1024 * 1024
MATCH_BYTES = 16 * 1024 * 1024
ERROR_BYTES = 4 * 1024


class InvalidResponse(Exception):
    pass


class ApiFailure(Exception):
    def __init__(self, status, body, token):
        self.status = status
        try:
            error = json.loads(body).get("error")
            if not isinstance(error, dict):
                raise ValueError("missing error envelope")
            self.code = str(error.get("code", "http_error"))
            self.message = str(error.get("message", ""))
        except (ValueError, AttributeError, TypeError):
            self.code = "http_error"
            self.message = body.decode("utf-8", errors="replace")
        self.code = clean(self.code, token)
        self.message = clean(self.message, token)


def clean(value, token):
    return "".join(char if char.isprintable() else " " for char in value.replace(token, "[redacted]"))[:ERROR_BYTES]


def redact(value, token):
    if isinstance(value, str):
        return value.replace(token, "[redacted]")
    if isinstance(value, list):
        return [redact(item, token) for item in value]
    if isinstance(value, dict):
        return {redact(key, token): redact(item, token) for key, item in value.items()}
    return value


def origin(value, parser):
    try:
        parts = urlsplit(value)
        host = parts.hostname
    except ValueError:
        parser.error("--base-url must be a valid numeric loopback HTTP origin")
    if parts.scheme != "http" or parts.username or parts.password or parts.path not in ("", "/") \
            or parts.query or parts.fragment or not host or parts.netloc.endswith(":"):
        parser.error("--base-url must be a loopback HTTP origin without credentials or a path")
    try:
        local = ipaddress.ip_address(host).is_loopback
        port = parts.port if parts.port is not None else 80
    except ValueError:
        parser.error("--base-url must be a valid loopback HTTP origin")
    if not local or port == 0:
        parser.error("--base-url must be a loopback HTTP origin")
    return host, port


def arguments(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--workspace-id", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--limit", type=int, default=100)
    parser.add_argument("--max-pages", type=int, default=1000)
    args = parser.parse_args(argv)
    args.host, args.port = origin(args.base_url, parser)
    for field in ("workspace_id", "run_id"):
        try:
            setattr(args, field, str(uuid.UUID(getattr(args, field))))
        except ValueError:
            parser.error(f"--{field.replace('_', '-')} must be a UUID")
    if not 1 <= args.limit <= 200:
        parser.error("--limit must be between 1 and 200")
    if args.max_pages < 1:
        parser.error("--max-pages must be positive")
    token = os.environ.get("LUMEN_BEARER_TOKEN", "")
    if not token or any(ord(char) < 32 or ord(char) == 127 for char in token):
        parser.error("LUMEN_BEARER_TOKEN must be set to a valid disposable local token")
    return args, token


def read_page(args, after, token):
    path = f"/api/v1/workspaces/{args.workspace_id}/audit?{urlencode({'after': after, 'limit': args.limit})}"
    connection = http.client.HTTPConnection(args.host, args.port, timeout=5)
    try:
        connection.request("GET", path, headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        })
        response = connection.getresponse()
        status = response.status
        body = response.read((SUCCESS_BYTES if status == 200 else ERROR_BYTES) + 1)
    finally:
        connection.close()
    if status != 200:
        raise ApiFailure(status, body[:ERROR_BYTES], token)
    if len(body) > SUCCESS_BYTES:
        raise InvalidResponse("audit success body exceeds 32 MiB")
    try:
        value = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        raise InvalidResponse("audit success body is not JSON") from None
    if not isinstance(value, dict) or not isinstance(value.get("events"), list):
        raise InvalidResponse("audit success body is missing an events array")
    events = value["events"]
    if len(events) > args.limit:
        raise InvalidResponse("audit page exceeds requested limit")
    previous = after
    for event in events:
        if not isinstance(event, dict) or type(event.get("sequence")) is not int \
                or event["sequence"] <= previous or event.get("workspace_id") != args.workspace_id \
                or not isinstance(event.get("payload"), dict):
            raise InvalidResponse("audit page has invalid sequence, workspace, or payload")
        previous = event["sequence"]
    return events


def main(argv=None):
    args, token = arguments(argv)
    after, matches, match_bytes = 0, [], 0
    for page in range(1, args.max_pages + 1):
        try:
            events = read_page(args, after, token)
        except ApiFailure as error:
            print(f"api_error status={error.status} code={error.code} message={error.message}", file=sys.stderr)
            return 3
        except InvalidResponse as error:
            print(f"invalid_response page={page} after={after} detail={error}", file=sys.stderr)
            return 4
        except (OSError, http.client.HTTPException) as error:
            print(f"transport_error page={page} after={after} detail={clean(str(error), token)}", file=sys.stderr)
            return 2
        for event in events:
            after = event["sequence"]
            if event["payload"].get("run_id") == args.run_id:
                match = redact(event, token)
                match_bytes += len(json.dumps(match, ensure_ascii=False).encode("utf-8")) + 1
                if match_bytes > MATCH_BYTES:
                    print(f"incomplete_pagination output_limit={MATCH_BYTES} after={after}", file=sys.stderr)
                    return 5
                matches.append(match)
        if len(events) < args.limit:
            category = "matching_events" if matches else "no_matching_events"
            report = {"category": category, "pages": page, "last_sequence": after, "events": matches}
            print(json.dumps(report, ensure_ascii=False))
            return 0 if matches else 1
    print(f"incomplete_pagination pages={args.max_pages} after={after} matches_seen={len(matches)}", file=sys.stderr)
    return 5


if __name__ == "__main__":
    sys.exit(main())
