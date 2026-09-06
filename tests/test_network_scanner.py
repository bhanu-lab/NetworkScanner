from unittest.mock import Mock, patch
import pytest
from network_scanner import MetadataStore, NetworkScanner, ScanError, validate_mac, validate_nickname


def test_validation():
    assert validate_mac("AA:BB:CC:DD:EE:FF") == "aa:bb:cc:dd:ee:ff"
    assert validate_nickname("  TV  ") == "TV"
    with pytest.raises(ScanError): validate_mac("not-a-mac")
    with pytest.raises(ScanError): validate_nickname(" ")


def test_store_uses_separate_namespaces():
    client=Mock(); client.get.side_effect=["Kitchen TV","Acme"]
    store=MetadataStore(client)
    assert store.get_nickname("AA:BB:CC:DD:EE:FF") == "Kitchen TV"
    assert store.get_vendor("AA:BB:CC:DD:EE:FF") == "Acme"
    assert client.get.call_args_list[0].args[0].startswith("nickname:")
    assert client.get.call_args_list[1].args[0].startswith("vendor:")


def test_scan_rejects_unbounded_network():
    scanner=NetworkScanner(store=MetadataStore(),max_hosts=100)
    scanner.interfaces=Mock(return_value=[__import__('network_scanner').Interface('eth0','10.0.0.2','255.255.0.0','10.0.0.0/16',True)])
    with pytest.raises(ScanError,match="limit is 100"): scanner.scan('eth0')


def test_interfaces_parse_structured_ip_output():
    address='[{"ifname":"eth0","addr_info":[{"family":"inet","local":"192.168.1.5","prefixlen":24}]}]'
    route='[{"dst":"default","gateway":"192.168.1.1","dev":"eth0"}]'
    with patch('network_scanner.shutil.which',return_value='/usr/sbin/ip'), patch('network_scanner.subprocess.run') as run:
        run.side_effect=[Mock(returncode=0,stdout=address),Mock(returncode=0,stdout=route)]
        interfaces=NetworkScanner(store=MetadataStore()).interfaces()
    assert interfaces[0].network=='192.168.1.0/24'
    assert interfaces[0].netmask=='255.255.255.0'
    assert interfaces[0].is_default


def test_neighbour_table_parses_linux_output():
    output="192.168.1.10 dev eth0 lladdr AA:BB:CC:DD:EE:FF REACHABLE\n"
    with patch('network_scanner.shutil.which',return_value='/usr/sbin/ip'), patch('network_scanner.subprocess.run') as run:
        run.return_value=Mock(returncode=0,stdout=output)
        assert NetworkScanner._neighbour_table('eth0') == {'192.168.1.10':'aa:bb:cc:dd:ee:ff'}
