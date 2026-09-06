import socket
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from network_scanner import (
    Interface,
    MetadataStore,
    NetworkScanner,
    ScanError,
    validate_mac,
    validate_nickname,
)


def test_validation():
    assert validate_mac("AA:BB:CC:DD:EE:FF") == "aa:bb:cc:dd:ee:ff"
    assert validate_mac("AA-BB-CC-DD-EE-FF") == "aa:bb:cc:dd:ee:ff"
    assert validate_nickname("  TV  ") == "TV"
    with pytest.raises(ScanError):
        validate_mac("not-a-mac")
    with pytest.raises(ScanError):
        validate_mac("aa:bb-cc:dd:ee:ff")
    with pytest.raises(ScanError):
        validate_nickname(" ")


def test_store_uses_separate_namespaces():
    client = Mock()
    client.get.side_effect = ["Kitchen TV", "Acme"]
    store = MetadataStore(client)

    assert store.get_nickname("AA:BB:CC:DD:EE:FF") == "Kitchen TV"
    assert store.get_vendor("AA:BB:CC:DD:EE:FF") == "Acme"
    assert client.get.call_args_list[0].args[0].startswith("nickname:")
    assert client.get.call_args_list[1].args[0].startswith("vendor:")


def test_interfaces_use_cross_platform_psutil_data():
    fake_psutil = SimpleNamespace(
        net_if_addrs=Mock(return_value={
            "Wi-Fi": [SimpleNamespace(
                family=socket.AF_INET,
                address="192.168.1.5",
                netmask="255.255.255.0",
            )],
            "Offline": [SimpleNamespace(
                family=socket.AF_INET,
                address="10.0.0.2",
                netmask="255.255.255.0",
            )],
            "Loopback": [SimpleNamespace(
                family=socket.AF_INET,
                address="127.0.0.1",
                netmask="255.0.0.0",
            )],
        }),
        net_if_stats=Mock(return_value={
            "Wi-Fi": SimpleNamespace(isup=True),
            "Offline": SimpleNamespace(isup=False),
            "Loopback": SimpleNamespace(isup=True),
        }),
    )
    scanner = NetworkScanner(store=MetadataStore())

    with patch.dict(sys.modules, {"psutil": fake_psutil}), patch.object(
        scanner, "_default_local_ip", return_value="192.168.1.5"
    ):
        interfaces = scanner.interfaces()

    assert interfaces == [Interface(
        name="Wi-Fi",
        address="192.168.1.5",
        netmask="255.255.255.0",
        network="192.168.1.0/24",
        is_default=True,
    )]


def test_scan_rejects_unbounded_network():
    scanner = NetworkScanner(store=MetadataStore(), max_hosts=100)
    scanner.interfaces = Mock(return_value=[Interface(
        "eth0", "10.0.0.2", "255.255.0.0", "10.0.0.0/16", True
    )])

    with pytest.raises(ScanError, match="limit is 100"):
        scanner.scan("eth0")


def test_interface_identifier_selects_the_right_address():
    scanner = NetworkScanner(store=MetadataStore())
    scanner.interfaces = Mock(return_value=[
        Interface("Ethernet", "10.0.0.2", "255.255.255.0", "10.0.0.0/24"),
        Interface("Ethernet", "192.168.1.5", "255.255.255.0", "192.168.1.0/24"),
    ])

    selected = scanner.interface("Ethernet@192.168.1.5")

    assert selected.network == "192.168.1.0/24"


@pytest.mark.parametrize(
    ("system", "expected"),
    [
        ("Linux", ["ping", "-n", "-c", "1", "-W", "1", "-I", "eth0", "192.168.1.8"]),
        ("Darwin", ["ping", "-n", "-c", "1", "-W", "800", "-S", "192.168.1.5", "192.168.1.8"]),
        ("Windows", ["ping", "-n", "1", "-w", "800", "-S", "192.168.1.5", "192.168.1.8"]),
    ],
)
def test_ping_uses_native_platform_arguments(system, expected):
    scanner = NetworkScanner(store=MetadataStore(), timeout=.8)
    with patch("network_scanner.platform.system", return_value=system), patch(
        "network_scanner.shutil.which", return_value="ping"
    ), patch("network_scanner.subprocess.run", return_value=Mock(returncode=0)) as run:
        assert scanner._ping("192.168.1.8", "eth0", "192.168.1.5")

    assert run.call_args.args[0] == expected


def test_ping_timeout_marks_host_unavailable():
    scanner = NetworkScanner(store=MetadataStore(), timeout=.2)
    with patch("network_scanner.platform.system", return_value="Linux"), patch(
        "network_scanner.shutil.which", return_value="ping"
    ), patch(
        "network_scanner.subprocess.run",
        side_effect=subprocess.TimeoutExpired("ping", .2),
    ):
        assert not scanner._ping("192.168.1.8", "eth0", "192.168.1.5")


@pytest.mark.parametrize(
    ("system", "interface", "source_ip", "output", "expected"),
    [
        (
            "Linux",
            "eth0",
            "192.168.1.5",
            "default via 192.168.1.1 dev eth0 proto dhcp\n",
            "192.168.1.1",
        ),
        (
            "Darwin",
            "en0",
            "192.168.1.5",
            "   gateway: 192.168.1.1\n interface: en0\n",
            "192.168.1.1",
        ),
        (
            "Windows",
            "Wi-Fi",
            "192.168.1.5",
            "  0.0.0.0  0.0.0.0  10.0.0.1  10.0.0.5  5\n"
            "  0.0.0.0  0.0.0.0  192.168.1.1  192.168.1.5  25\n",
            "192.168.1.1",
        ),
    ],
)
def test_gateway_parsing_for_each_platform(system, interface, source_ip, output, expected):
    result = Mock(returncode=0, stdout=output)
    with patch("network_scanner.platform.system", return_value=system), patch(
        "network_scanner.shutil.which", side_effect=lambda command: command
    ), patch.object(NetworkScanner, "_run_command", return_value=result):
        assert NetworkScanner._gateway_for(interface, source_ip) == expected


def test_macos_gateway_must_match_selected_interface():
    result = Mock(
        returncode=0,
        stdout="gateway: 192.168.1.1\ninterface: en1\n",
    )
    with patch("network_scanner.platform.system", return_value="Darwin"), patch(
        "network_scanner.shutil.which", return_value="route"
    ), patch.object(NetworkScanner, "_run_command", return_value=result):
        assert NetworkScanner._gateway_for("en0", "192.168.1.5") is None


@pytest.mark.parametrize(
    ("system", "interface", "output"),
    [
        (
            "Linux",
            "eth0",
            "192.168.1.10 dev eth0 lladdr AA:BB:CC:DD:EE:FF REACHABLE\n",
        ),
        (
            "Darwin",
            "en0",
            "? (192.168.1.10) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]\n",
        ),
        (
            "Windows",
            "Wi-Fi",
            "  192.168.1.10          aa-bb-cc-dd-ee-ff     dynamic\n",
        ),
    ],
)
def test_neighbour_table_parsing_for_each_platform(system, interface, output):
    result = Mock(returncode=0, stdout=output)
    with patch("network_scanner.platform.system", return_value=system), patch(
        "network_scanner.shutil.which", side_effect=lambda command: command
    ), patch.object(NetworkScanner, "_run_command", return_value=result):
        neighbours = NetworkScanner._neighbour_table(interface, "192.168.1.5")

    assert neighbours == {"192.168.1.10": "aa:bb:cc:dd:ee:ff"}


def test_macos_neighbour_table_filters_other_interfaces():
    result = Mock(
        returncode=0,
        stdout=(
            "? (10.0.0.4) at 00:11:22:33:44:55 on en1 ifscope [ethernet]\n"
            "? (192.168.1.10) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]\n"
        ),
    )
    with patch("network_scanner.platform.system", return_value="Darwin"), patch(
        "network_scanner.shutil.which", return_value="arp"
    ), patch.object(NetworkScanner, "_run_command", return_value=result):
        neighbours = NetworkScanner._neighbour_table("en0", "192.168.1.5")

    assert neighbours == {"192.168.1.10": "aa:bb:cc:dd:ee:ff"}
