"""Command-line client for the Home Network Monitor HTTP API."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Callable, Sequence
from typing import Any, TextIO
from urllib.parse import quote, urlsplit

import requests

DEFAULT_SERVER_URL = "http://127.0.0.1:5000"
DEFAULT_TIMEOUT = 30.0


class ClientError(RuntimeError):
    """An actionable problem communicating with the scanner server."""


class NetworkScannerClient:
    """Small typed wrapper around the scanner's JSON API."""

    def __init__(
        self,
        base_url: str = DEFAULT_SERVER_URL,
        timeout: float = DEFAULT_TIMEOUT,
        session: requests.Session | None = None,
    ) -> None:
        normalized = base_url.strip().rstrip("/")
        parsed = urlsplit(normalized)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ClientError("Server URL must be an absolute http:// or https:// URL.")
        if parsed.query or parsed.fragment:
            raise ClientError("Server URL cannot contain a query string or fragment.")
        if timeout <= 0:
            raise ClientError("Timeout must be greater than zero seconds.")
        self.base_url = normalized
        self.timeout = timeout
        self.session = session or requests.Session()

    def _request(self, method: str, path: str, payload: dict | None = None) -> Any:
        url = f"{self.base_url}{path}"
        try:
            response = self.session.request(
                method,
                url,
                json=payload,
                timeout=self.timeout,
                headers={"Accept": "application/json"},
            )
        except requests.Timeout as error:
            raise ClientError(
                f"The scanner server did not respond within {self.timeout:g} seconds."
            ) from error
        except requests.ConnectionError as error:
            raise ClientError(f"Cannot connect to scanner server at {self.base_url}.") from error
        except requests.RequestException as error:
            raise ClientError(f"Request to scanner server failed: {error}") from error

        try:
            body = response.json()
        except ValueError as error:
            if response.ok:
                raise ClientError("Scanner server returned an invalid JSON response.") from error
            raise ClientError(f"Scanner server returned HTTP {response.status_code}.") from error

        if not response.ok:
            message = body.get("error") if isinstance(body, dict) else None
            raise ClientError(message or f"Scanner server returned HTTP {response.status_code}.")
        return body

    def health(self) -> dict[str, Any]:
        return self._expect_object(self._request("GET", "/api/health"), "health")

    def interfaces(self) -> list[dict[str, Any]]:
        body = self._request("GET", "/api/interfaces")
        if not isinstance(body, list) or any(not isinstance(item, dict) for item in body):
            raise ClientError("Scanner server returned an invalid interfaces response.")
        return body

    def scan(self, interface: str, details: bool = False) -> dict[str, Any]:
        payload: dict[str, Any] = {"interface": interface}
        if details:
            payload["details"] = True
        body = self._request("POST", "/api/scans", payload)
        return self._expect_object(body, "scan")

    def nicknames(self) -> dict[str, str]:
        body = self._request("GET", "/api/nicknames")
        if not isinstance(body, dict) or any(
            not isinstance(key, str) or not isinstance(value, str)
            for key, value in body.items()
        ):
            raise ClientError("Scanner server returned an invalid nicknames response.")
        return body

    def set_nickname(self, mac_address: str, nickname: str) -> dict[str, Any]:
        mac = quote(mac_address, safe="")
        body = self._request(
            "PUT",
            f"/api/devices/{mac}/nickname",
            {"nickname": nickname},
        )
        return self._expect_object(body, "nickname")

    @staticmethod
    def _expect_object(body: Any, operation: str) -> dict[str, Any]:
        if not isinstance(body, dict):
            raise ClientError(f"Scanner server returned an invalid {operation} response.")
        return body


def _positive_float(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a number") from error
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def _add_json_option(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--json", action="store_true", help="print the raw JSON response")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netscan",
        description="Inspect a Home Network Monitor server from the terminal.",
    )
    parser.add_argument(
        "--server",
        default=os.getenv("NETSCAN_SERVER_URL", DEFAULT_SERVER_URL),
        help="scanner server URL (default: %(default)s; env: NETSCAN_SERVER_URL)",
    )
    parser.add_argument(
        "--timeout",
        type=_positive_float,
        default=DEFAULT_TIMEOUT,
        help="HTTP timeout in seconds (default: %(default)g)",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    health = commands.add_parser("health", help="check server availability")
    _add_json_option(health)

    interfaces = commands.add_parser("interfaces", help="list server network interfaces")
    _add_json_option(interfaces)

    scan = commands.add_parser("scan", help="scan an interface and list discovered devices")
    scan.add_argument(
        "-i",
        "--interface",
        help="interface ID from the interfaces command; defaults to the primary interface",
    )
    scan.add_argument(
        "--details",
        action="store_true",
        help="probe services and UPnP metadata to infer make, model, OS, and type",
    )
    _add_json_option(scan)

    nicknames = commands.add_parser("nicknames", help="list saved device nicknames")
    _add_json_option(nicknames)

    nickname = commands.add_parser("nickname", help="set a nickname for a device MAC address")
    nickname.add_argument("mac_address", help="device MAC address")
    nickname.add_argument("name", nargs="+", help="nickname; quotes are optional")
    _add_json_option(nickname)
    return parser


def _clean_cell(value: Any, limit: int = 40) -> str:
    if value is None or value == "":
        return "-"
    text = " ".join(str(value).split())
    return text if len(text) <= limit else f"{text[:limit - 1]}…"


def _print_table(headers: Sequence[str], rows: Sequence[Sequence[Any]], output: TextIO) -> None:
    rendered = [[_clean_cell(value) for value in row] for row in rows]
    widths = [len(header) for header in headers]
    for row in rendered:
        for index, value in enumerate(row):
            widths[index] = max(widths[index], len(value))

    def line(values: Sequence[str]) -> str:
        return "  ".join(value.ljust(widths[index]) for index, value in enumerate(values)).rstrip()

    print(line(headers), file=output)
    print(line(["-" * width for width in widths]), file=output)
    for row in rendered:
        print(line(row), file=output)


def _print_json(body: Any, output: TextIO) -> None:
    print(json.dumps(body, indent=2, sort_keys=True), file=output)


def _select_interface(client: NetworkScannerClient, requested: str | None) -> str:
    if requested:
        return requested
    interfaces = client.interfaces()
    if not interfaces:
        raise ClientError("The scanner server found no usable IPv4 interfaces.")
    defaults = [item for item in interfaces if item.get("is_default")]
    candidates = defaults or interfaces
    if len(candidates) != 1 and not defaults:
        choices = ", ".join(str(item.get("id") or item.get("name")) for item in interfaces)
        raise ClientError(f"Choose an interface with --interface. Available: {choices}")
    selected = candidates[0]
    identifier = selected.get("id") or selected.get("name")
    if not isinstance(identifier, str) or not identifier:
        raise ClientError("Scanner server returned an interface without an ID.")
    return identifier


def _execute(args: argparse.Namespace, client: NetworkScannerClient, output: TextIO) -> None:
    if args.command == "health":
        body = client.health()
        if args.json:
            _print_json(body, output)
            return
        print(f"Status: {body.get('status', 'unknown')}", file=output)
        persistence = "enabled" if body.get("persistence") else "disabled"
        print(f"Nickname persistence: {persistence}", file=output)
        return

    if args.command == "interfaces":
        body = client.interfaces()
        if args.json:
            _print_json(body, output)
            return
        rows = [
            (
                item.get("id") or item.get("name"),
                item.get("address"),
                item.get("network"),
                "yes" if item.get("is_default") else "no",
            )
            for item in body
        ]
        _print_table(("ID", "ADDRESS", "NETWORK", "DEFAULT"), rows, output)
        return

    if args.command == "scan":
        interface = _select_interface(client, args.interface)
        body = client.scan(interface, details=args.details)
        if args.json:
            _print_json(body, output)
            return
        print(
            f"Found {body.get('count', 0)} device(s) on {body.get('interface', interface)} "
            f"in {body.get('duration_seconds', 0)}s.",
            file=output,
        )
        devices = body.get("devices")
        if not isinstance(devices, list):
            raise ClientError("Scanner server returned an invalid device list.")
        rows = []
        for device in devices:
            if not isinstance(device, dict):
                raise ClientError("Scanner server returned an invalid device entry.")
            flags = []
            if device.get("is_local"):
                flags.append("local")
            if device.get("is_gateway"):
                flags.append("gateway")
            rows.append((
                device.get("ip_address"),
                device.get("nickname") or device.get("friendly_name") or device.get("hostname"),
                device.get("mac_address"),
                device.get("vendor"),
                device.get("model"),
                (
                    f"{device.get('operating_system')} ({device.get('os_confidence')})"
                    if device.get("operating_system") and device.get("os_confidence")
                    else device.get("operating_system")
                ),
                device.get("device_type"),
                ", ".join(
                    f"{service.get('name')}:{service.get('port')}"
                    for service in device.get("services", [])
                    if isinstance(service, dict)
                ),
                ", ".join(flags),
            ))
        _print_table(
            ("IP", "NAME", "MAC", "MAKE", "MODEL", "OS", "TYPE", "SERVICES", "FLAGS"),
            rows,
            output,
        )
        return

    if args.command == "nicknames":
        body = client.nicknames()
        if args.json:
            _print_json(body, output)
            return
        _print_table(("MAC", "NICKNAME"), sorted(body.items()), output)
        return

    if args.command == "nickname":
        body = client.set_nickname(args.mac_address, " ".join(args.name))
        if args.json:
            _print_json(body, output)
            return
        print(f"{body.get('mac_address', args.mac_address)}: {body.get('nickname')}", file=output)
        return

    raise ClientError(f"Unsupported command: {args.command}")


def main(
    argv: Sequence[str] | None = None,
    *,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
    client_factory: Callable[..., NetworkScannerClient] = NetworkScannerClient,
) -> int:
    output = stdout or sys.stdout
    errors = stderr or sys.stderr
    args = build_parser().parse_args(argv)
    try:
        client = client_factory(args.server, timeout=args.timeout)
        _execute(args, client, output)
    except ClientError as error:
        print(f"Error: {error}", file=errors)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
