from unittest.mock import Mock, patch

from fingerprint import DeviceFingerprinter, FingerprintTarget


def test_service_fingerprint_infers_windows_computer():
    fingerprinter = DeviceFingerprinter()
    target = FingerprintTarget("192.168.1.10", hostname="office-pc")
    with patch.object(
        fingerprinter, "_scan_ports", return_value={target.ip_address: {3389, 445}}
    ), patch.object(fingerprinter, "_ssdp_records", return_value={}):
        result = fingerprinter.inspect([target], "192.168.1.5")[target.ip_address]

    assert result.operating_system == "Windows"
    assert result.os_confidence == "medium"
    assert result.device_type == "computer"
    assert [service.name for service in result.services] == ["smb", "rdp"]
    assert result.sources == ["tcp-services"]


def test_upnp_metadata_identifies_smart_tv_make_model_and_os():
    fingerprinter = DeviceFingerprinter()
    target = FingerprintTarget("192.168.1.20", manufacturer="Samsung Electronics")
    records = {
        target.ip_address: [{
            "server": "Linux UPnP/1.0 Tizen/8.0",
            "location": "http://192.168.1.20:8001/description.xml",
        }]
    }
    metadata = {
        "manufacturer": "Samsung",
        "modelName": "QE55Q80",
        "modelDescription": "Tizen Smart TV",
        "friendlyName": "Living Room TV",
        "deviceType": "urn:schemas-upnp-org:device:MediaRenderer:1",
    }
    with patch.object(
        fingerprinter, "_scan_ports", return_value={target.ip_address: {8008}}
    ), patch.object(
        fingerprinter, "_ssdp_records", return_value=records
    ), patch.object(fingerprinter, "_fetch_description", return_value=metadata):
        result = fingerprinter.inspect([target], "192.168.1.5")[target.ip_address]

    assert result.manufacturer == "Samsung"
    assert result.model == "QE55Q80"
    assert result.friendly_name == "Living Room TV"
    assert result.operating_system == "Tizen"
    assert result.os_confidence == "high"
    assert result.device_type == "smart TV"
    assert result.sources == ["mac-vendor", "tcp-services", "ssdp", "upnp-description"]


def test_ssdp_parser_normalizes_headers():
    result = DeviceFingerprinter._parse_ssdp(
        b"HTTP/1.1 200 OK\r\nLOCATION: http://192.168.1.2/device.xml\r\n"
        b"Server: Linux UPnP/1.0\r\n\r\n"
    )

    assert result == {
        "location": "http://192.168.1.2/device.xml",
        "server": "Linux UPnP/1.0",
    }


def test_upnp_description_rejects_a_location_on_another_host():
    session = Mock()
    fingerprinter = DeviceFingerprinter(session=session)

    assert fingerprinter._fetch_description(
        "http://203.0.113.10/device.xml", "192.168.1.20"
    ) == {}
    session.get.assert_not_called()
