import json
from io import StringIO
from threading import Thread
from unittest.mock import Mock

import requests
from werkzeug.serving import make_server

from main import create_app
from netscan_client import ClientError, NetworkScannerClient, main
from network_scanner import Device, Interface, MetadataStore


def response(status: int, body) -> requests.Response:
    result = requests.Response()
    result.status_code = status
    result._content = json.dumps(body).encode()
    result.headers["Content-Type"] = "application/json"
    return result


def test_api_client_sends_scan_request():
    session = Mock()
    session.request.return_value = response(200, {
        "interface": "en0@192.168.1.5",
        "count": 0,
        "devices": [],
        "duration_seconds": .1,
    })
    client = NetworkScannerClient("http://scanner.local:5000/", 5, session)

    result = client.scan("en0@192.168.1.5")

    assert result["count"] == 0
    session.request.assert_called_once_with(
        "POST",
        "http://scanner.local:5000/api/scans",
        json={"interface": "en0@192.168.1.5"},
        timeout=5,
        headers={"Accept": "application/json"},
    )


def test_api_client_surfaces_server_error():
    session = Mock()
    session.request.return_value = response(400, {"error": "bad interface"})
    client = NetworkScannerClient(session=session)

    try:
        client.scan("missing")
    except ClientError as error:
        assert str(error) == "bad interface"
    else:
        raise AssertionError("ClientError was not raised")


def test_api_client_surfaces_connection_error():
    session = Mock()
    session.request.side_effect = requests.ConnectionError("refused")
    client = NetworkScannerClient("http://scanner.local:5000", session=session)

    try:
        client.health()
    except ClientError as error:
        assert "Cannot connect" in str(error)
    else:
        raise AssertionError("ClientError was not raised")


def test_client_and_server_exchange_detailed_device_data_over_http():
    class Scanner:
        store = MetadataStore()

        def interfaces(self):
            return [Interface(
                "eth0", "192.168.1.5", "255.255.255.0", "192.168.1.0/24", True
            )]

        def scan(self, interface, details=False):
            device = Device(
                "192.168.1.20",
                vendor="Samsung",
                model="QE55Q80",
                operating_system="Tizen" if details else None,
                os_confidence="high" if details else None,
                device_type="smart TV" if details else "network device",
            )
            return [device.to_dict()], .1

    server = make_server("127.0.0.1", 0, create_app(Scanner()))
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        client = NetworkScannerClient(f"http://127.0.0.1:{server.server_port}")
        assert client.health()["status"] == "ok"
        interface = client.interfaces()[0]["id"]
        result = client.scan(interface, details=True)
    finally:
        server.shutdown()
        thread.join(timeout=2)

    assert result["details"] is True
    assert result["devices"][0]["model"] == "QE55Q80"
    assert result["devices"][0]["operating_system"] == "Tizen"


class FakeClient:
    def __init__(self, _server, timeout):
        self.timeout = timeout
        self.selected = None
        self.details = False
        self.nickname = None

    def health(self):
        return {"status": "ok", "persistence": False}

    def interfaces(self):
        return [{
            "id": "Wi-Fi@192.168.1.5",
            "name": "Wi-Fi",
            "address": "192.168.1.5",
            "network": "192.168.1.0/24",
            "is_default": True,
        }]

    def scan(self, interface, details=False):
        self.selected = interface
        self.details = details
        return {
            "interface": interface,
            "count": 1,
            "duration_seconds": .12,
            "devices": [{
                "ip_address": "192.168.1.1",
                "mac_address": "aa:bb:cc:dd:ee:ff",
                "hostname": "router.local",
                "friendly_name": "Home Router",
                "vendor": "Acme",
                "model": "Router 1000",
                "nickname": "Router",
                "device_type": "router",
                "operating_system": "Linux",
                "os_confidence": "high",
                "services": [{"port": 80, "name": "http", "protocol": "tcp"}],
                "is_local": False,
                "is_gateway": True,
            }],
        }

    def nicknames(self):
        return {"aa:bb:cc:dd:ee:ff": "Router"}

    def set_nickname(self, mac_address, nickname):
        self.nickname = (mac_address, nickname)
        return {"mac_address": mac_address.lower(), "nickname": nickname}


def test_scan_command_selects_default_interface_and_prints_devices():
    created = []

    def factory(server, timeout):
        client = FakeClient(server, timeout)
        created.append(client)
        return client

    output = StringIO()
    assert main(["scan", "--details"], stdout=output, client_factory=factory) == 0

    assert created[0].selected == "Wi-Fi@192.168.1.5"
    assert created[0].details is True
    assert "Found 1 device(s)" in output.getvalue()
    assert "Router 1000" in output.getvalue()
    assert "Linux (high)" in output.getvalue()
    assert "gateway" in output.getvalue()


def test_interfaces_command_can_print_json():
    output = StringIO()

    assert main(
        ["interfaces", "--json"],
        stdout=output,
        client_factory=FakeClient,
    ) == 0

    assert json.loads(output.getvalue())[0]["name"] == "Wi-Fi"


def test_nickname_command_joins_unquoted_words():
    created = []

    def factory(server, timeout):
        client = FakeClient(server, timeout)
        created.append(client)
        return client

    output = StringIO()
    assert main(
        ["nickname", "AA:BB:CC:DD:EE:FF", "Kitchen", "TV"],
        stdout=output,
        client_factory=factory,
    ) == 0

    assert created[0].nickname == ("AA:BB:CC:DD:EE:FF", "Kitchen TV")
    assert "Kitchen TV" in output.getvalue()
