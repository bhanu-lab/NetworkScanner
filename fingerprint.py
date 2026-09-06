"""Best-effort device fingerprinting for hosts already found on a local network."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
import ipaddress
import socket
import time
from typing import Iterable
from urllib.parse import urlsplit
from xml.etree import ElementTree

import requests


@dataclass(frozen=True)
class FingerprintTarget:
    ip_address: str
    hostname: str | None = None
    manufacturer: str | None = None
    is_gateway: bool = False


@dataclass(frozen=True)
class Service:
    port: int
    name: str
    protocol: str = "tcp"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Fingerprint:
    manufacturer: str | None = None
    model: str | None = None
    friendly_name: str | None = None
    operating_system: str | None = None
    os_confidence: str | None = None
    device_type: str | None = None
    services: list[Service] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)


class DeviceFingerprinter:
    """Identify common home devices using TCP services and UPnP/SSDP metadata."""

    SERVICE_PORTS = {
        22: "ssh",
        53: "dns",
        80: "http",
        139: "netbios",
        443: "https",
        445: "smb",
        548: "afp",
        631: "ipp",
        3389: "rdp",
        5357: "ws-discovery",
        5555: "adb",
        8008: "cast-http",
        8009: "cast",
        9100: "printer",
        32400: "plex",
        62078: "apple-sync",
    }

    def __init__(self, timeout: float = .3, max_workers: int = 64,
                 ssdp_timeout: float = .8, session: requests.Session | None = None):
        self.timeout = max(.05, timeout)
        self.max_workers = max(1, min(max_workers, 256))
        self.ssdp_timeout = max(.1, ssdp_timeout)
        self.session = session or requests.Session()

    def inspect(self, targets: Iterable[FingerprintTarget], source_ip: str) -> dict[str, Fingerprint]:
        targets = list(targets)
        if not targets:
            return {}
        addresses = {target.ip_address for target in targets}
        ports = self._scan_ports(addresses, source_ip)
        records = self._ssdp_records(source_ip, addresses)
        return {
            target.ip_address: self._identify(target, ports.get(target.ip_address, set()),
                                               records.get(target.ip_address, []))
            for target in targets
        }

    def _scan_ports(self, addresses: set[str], source_ip: str) -> dict[str, set[int]]:
        found = {address: set() for address in addresses}
        tasks = [(address, port) for address in addresses for port in self.SERVICE_PORTS]
        if not tasks:
            return found
        with ThreadPoolExecutor(max_workers=min(self.max_workers, len(tasks))) as pool:
            futures = {
                pool.submit(self._port_open, address, port, source_ip): (address, port)
                for address, port in tasks
            }
            for future in as_completed(futures):
                address, port = futures[future]
                try:
                    if future.result():
                        found[address].add(port)
                except OSError:
                    continue
        return found

    def _port_open(self, address: str, port: int, source_ip: str) -> bool:
        try:
            with socket.create_connection(
                (address, port), timeout=self.timeout, source_address=(source_ip, 0)
            ):
                return True
        except (OSError, TimeoutError):
            return False

    def _ssdp_records(self, source_ip: str, addresses: set[str]) -> dict[str, list[dict[str, str]]]:
        records: dict[str, list[dict[str, str]]] = {}
        message = (
            "M-SEARCH * HTTP/1.1\r\n"
            "HOST: 239.255.255.250:1900\r\n"
            'MAN: "ssdp:discover"\r\n'
            "MX: 1\r\n"
            "ST: ssdp:all\r\n\r\n"
        ).encode("ascii")
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
                sock.settimeout(min(.2, self.ssdp_timeout))
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(source_ip))
                sock.bind((source_ip, 0))
                sock.sendto(message, ("239.255.255.250", 1900))
                deadline = time.monotonic() + self.ssdp_timeout
                while time.monotonic() < deadline:
                    try:
                        payload, sender = sock.recvfrom(65535)
                    except socket.timeout:
                        continue
                    address = sender[0]
                    if address not in addresses:
                        continue
                    record = self._parse_ssdp(payload)
                    if record and record not in records.setdefault(address, []):
                        records[address].append(record)
        except OSError:
            return records
        return records

    @staticmethod
    def _parse_ssdp(payload: bytes) -> dict[str, str]:
        lines = payload.decode("iso-8859-1", errors="replace").splitlines()
        if not lines or "200" not in lines[0]:
            return {}
        record = {}
        for line in lines[1:]:
            name, separator, value = line.partition(":")
            if separator and name.strip():
                record[name.strip().lower()] = value.strip()
        return record

    def _identify(self, target: FingerprintTarget, ports: set[int],
                  records: list[dict[str, str]]) -> Fingerprint:
        metadata: dict[str, str] = {}
        servers = []
        for record in records:
            if server := record.get("server"):
                servers.append(server)
            location = record.get("location")
            if location and not metadata:
                metadata = self._fetch_description(location, target.ip_address)

        evidence = " ".join(filter(None, [
            target.hostname,
            target.manufacturer,
            *servers,
            *metadata.values(),
        ])).lower()
        operating_system, confidence = self._infer_os(evidence, ports)
        device_type = self._infer_type(evidence, ports, target.is_gateway)
        sources = []
        if target.manufacturer:
            sources.append("mac-vendor")
        if ports:
            sources.append("tcp-services")
        if records:
            sources.append("ssdp")
        if metadata:
            sources.append("upnp-description")

        return Fingerprint(
            manufacturer=metadata.get("manufacturer") or target.manufacturer,
            model=metadata.get("modelName") or metadata.get("modelDescription"),
            friendly_name=metadata.get("friendlyName"),
            operating_system=operating_system,
            os_confidence=confidence,
            device_type=device_type,
            services=[Service(port, self.SERVICE_PORTS[port]) for port in sorted(ports)],
            sources=sources,
        )

    def _fetch_description(self, location: str, expected_ip: str) -> dict[str, str]:
        parsed = urlsplit(location)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return {}
        try:
            if ipaddress.ip_address(parsed.hostname) != ipaddress.ip_address(expected_ip):
                return {}
        except ValueError:
            return {}
        try:
            response = self.session.get(
                location,
                timeout=max(1.0, self.timeout * 3),
                headers={"Accept": "application/xml", "User-Agent": "NetworkScanner/1"},
            )
            if not response.ok:
                return {}
            root = ElementTree.fromstring(response.content[:262144])
        except (requests.RequestException, ElementTree.ParseError, ValueError):
            return {}
        wanted = {"manufacturer", "modelName", "modelDescription", "friendlyName", "deviceType"}
        result = {}
        for element in root.iter():
            name = element.tag.rsplit("}", 1)[-1]
            value = (element.text or "").strip()
            if name in wanted and value and name not in result:
                result[name] = value[:200]
        return result

    @staticmethod
    def _infer_os(evidence: str, ports: set[int]) -> tuple[str | None, str | None]:
        explicit = (
            (("ipad",), "iPadOS"),
            (("iphone", "apple ios", "iphone os"), "iOS"),
            (("android",), "Android"),
            (("windows",), "Windows"),
            (("mac os", "macos", "macbook", "imac"), "macOS"),
            (("tizen",), "Tizen"),
            (("webos", "web os"), "webOS"),
            (("roku",), "Roku OS"),
            (("chromecast", "google tv"), "Google Cast / Android"),
            (("linux", "ubuntu", "debian"), "Linux"),
        )
        for needles, name in explicit:
            if any(needle in evidence for needle in needles):
                return name, "high"
        if 62078 in ports:
            return "iOS / iPadOS", "medium"
        if 3389 in ports:
            return "Windows", "medium"
        if 5555 in ports:
            return "Android", "medium"
        if 445 in ports:
            return "Windows / Samba", "low"
        if 548 in ports:
            return "macOS / NAS", "low"
        if 22 in ports:
            return "Unix-like", "low"
        return None, None

    @staticmethod
    def _infer_type(evidence: str, ports: set[int], is_gateway: bool) -> str | None:
        if is_gateway:
            return "router"
        keywords = (
            (("printer", "jetdirect"), "printer"),
            (("television", "smart tv", "mediarenderer", "tizen", "webos"), "smart TV"),
            (("camera", "doorbell"), "camera"),
            (("iphone", "android phone", "smartphone"), "phone"),
            (("ipad", "tablet"), "tablet"),
            (("speaker", "homepod", "sonos"), "smart speaker"),
            (("chromecast", "roku", "google tv"), "streaming device"),
            (("nas", "diskstation", "storage"), "network storage"),
        )
        for needles, device_type in keywords:
            if any(needle in evidence for needle in needles):
                return device_type
        if ports & {631, 9100}:
            return "printer"
        if ports & {8008, 8009}:
            return "streaming device"
        if 32400 in ports:
            return "media server"
        if ports & {3389, 445, 548}:
            return "computer"
        return None
