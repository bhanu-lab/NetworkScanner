"""Reliable, CIDR-aware discovery of devices on a local IPv4 network."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
import ipaddress
import logging
import os
import platform
import re
import shutil
import socket
import subprocess
import time
from typing import Iterable

import redis
import requests

LOG = logging.getLogger(__name__)
MAC_PATTERN = re.compile(r"(?i)\b([0-9a-f]{2}(?::[0-9a-f]{2}){5})\b")


class ScanError(RuntimeError):
    """A user-actionable scan failure."""


@dataclass(frozen=True)
class Interface:
    name: str
    address: str
    netmask: str
    network: str
    is_default: bool = False


@dataclass
class Device:
    ip_address: str
    mac_address: str | None = None
    hostname: str | None = None
    vendor: str | None = None
    nickname: str | None = None
    device_type: str = "unknown"
    is_local: bool = False
    is_gateway: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


class MetadataStore:
    """Optional Redis-backed nickname and vendor cache."""

    def __init__(self, client: redis.Redis | None = None):
        self.client = client

    @classmethod
    def from_environment(cls) -> "MetadataStore":
        url, host = os.getenv("REDIS_URL"), os.getenv("REDIS_HOST")
        if not url and not host:
            return cls()
        try:
            client = redis.Redis.from_url(url, decode_responses=True) if url else redis.Redis(
                host=host, port=int(os.getenv("REDIS_PORT", "6379")),
                password=os.getenv("REDIS_PASS") or None, decode_responses=True,
                socket_connect_timeout=.5, socket_timeout=.5,
            )
            client.ping()
            return cls(client)
        except (redis.RedisError, ValueError):
            LOG.warning("Redis unavailable; continuing without persistence")
            return cls()

    @staticmethod
    def _mac(mac: str) -> str:
        return mac.strip().lower()

    def _get(self, prefix: str, mac: str | None) -> str | None:
        if not self.client or not mac:
            return None
        try:
            return self.client.get(f"{prefix}:{self._mac(mac)}")
        except redis.RedisError:
            return None

    def get_nickname(self, mac: str | None) -> str | None:
        return self._get("nickname", mac)

    def get_vendor(self, mac: str | None) -> str | None:
        return self._get("vendor", mac)

    def set_nickname(self, mac: str, nickname: str) -> None:
        if not self.client:
            raise ScanError("Nickname storage is disabled. Configure REDIS_URL or REDIS_HOST.")
        self.client.set(f"nickname:{self._mac(mac)}", nickname)

    def set_vendor(self, mac: str, vendor: str) -> None:
        if self.client:
            try:
                self.client.set(f"vendor:{self._mac(mac)}", vendor)
            except redis.RedisError:
                LOG.warning("Could not cache vendor for %s", mac)

    def all_nicknames(self) -> dict[str, str]:
        if not self.client:
            return {}
        try:
            return {key.removeprefix("nickname:"): self.client.get(key) or ""
                    for key in self.client.scan_iter(match="nickname:*")}
        except redis.RedisError:
            return {}


class NetworkScanner:
    def __init__(self, store: MetadataStore | None = None, max_workers: int = 64,
                 timeout: float = .8, max_hosts: int = 1024,
                 vendor_lookup: bool | None = None):
        self.store = store or MetadataStore.from_environment()
        self.max_workers = max(1, min(max_workers, 256))
        self.timeout = max(.1, timeout)
        self.max_hosts = max(1, max_hosts)
        self.vendor_lookup = (os.getenv("VENDOR_LOOKUP", "false").lower() in
                              {"1", "true", "yes"}) if vendor_lookup is None else vendor_lookup

    def interfaces(self) -> list[Interface]:
        executable = shutil.which("ip")
        if not executable:
            raise ScanError("The 'ip' command is required to inspect network interfaces.")
        address_result = subprocess.run(
            [executable, "-j", "-4", "address", "show"], capture_output=True,
            text=True, check=False,
        )
        route_result = subprocess.run(
            [executable, "-j", "-4", "route", "show", "default"], capture_output=True,
            text=True, check=False,
        )
        if address_result.returncode:
            raise ScanError("Unable to read network interfaces using 'ip address'.")
        import json
        try:
            addresses = json.loads(address_result.stdout)
            routes = json.loads(route_result.stdout) if not route_result.returncode else []
        except json.JSONDecodeError as error:
            raise ScanError("The 'ip' command returned invalid network information.") from error
        default_name = routes[0].get("dev") if routes else None
        result = []
        for link in addresses:
            name = link.get("ifname", "")
            for item in link.get("addr_info", []):
                address, prefix = item.get("local"), item.get("prefixlen")
                if item.get("family") != "inet" or not address or address.startswith("127."):
                    continue
                try:
                    interface = ipaddress.ip_interface(f"{address}/{prefix}")
                except ValueError:
                    continue
                result.append(Interface(name, address, str(interface.netmask),
                                        str(interface.network), name == default_name))
        return sorted(result, key=lambda item: (not item.is_default, item.name))

    def interface(self, name: str) -> Interface:
        match = next((item for item in self.interfaces() if item.name == name), None)
        if not match:
            raise ScanError(f"Interface '{name}' has no usable IPv4 address.")
        return match

    def scan(self, interface_name: str) -> tuple[list[dict], float]:
        interface = self.interface(interface_name)
        network = ipaddress.ip_network(interface.network)
        host_count = max(0, network.num_addresses - 2)
        if host_count > self.max_hosts:
            raise ScanError(f"Network {network} contains {host_count} hosts; limit is {self.max_hosts}. "
                            "Set NETSCAN_MAX_HOSTS if this is intentional.")
        started = time.monotonic()
        gateway = self._gateway_for(interface_name)
        live = self._discover(network.hosts(), interface_name, interface.address)
        neighbours = self._neighbour_table(interface_name)
        devices = []
        for ip in sorted(live, key=ipaddress.ip_address):
            mac = neighbours.get(ip)
            local, router = ip == interface.address, ip == gateway
            devices.append(Device(
                ip_address=ip, mac_address=mac, hostname=self._hostname(ip),
                vendor=self._vendor(mac), nickname=self.store.get_nickname(mac),
                device_type="this device" if local else "router" if router else "network device",
                is_local=local, is_gateway=router,
            ).to_dict())
        return devices, round(time.monotonic() - started, 3)

    def _discover(self, hosts: Iterable[ipaddress.IPv4Address], interface: str,
                  local_ip: str) -> set[str]:
        live = {local_ip}
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {pool.submit(self._ping, str(host), interface): str(host)
                       for host in hosts if str(host) != local_ip}
            for future in as_completed(futures):
                try:
                    if future.result():
                        live.add(futures[future])
                except OSError as error:
                    raise ScanError(str(error)) from error
        return live

    def _ping(self, ip: str, interface: str) -> bool:
        executable = shutil.which("ping")
        if not executable:
            raise OSError("The 'ping' command is required but was not found.")
        if platform.system() == "Darwin":
            command = [executable, "-c", "1", "-W", str(int(self.timeout * 1000)), ip]
        else:
            command = [executable, "-c", "1", "-W", str(max(1, round(self.timeout))),
                       "-I", interface, ip]
        try:
            return subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                  check=False, timeout=self.timeout + 1).returncode == 0
        except subprocess.TimeoutExpired:
            return False

    @staticmethod
    def _hostname(ip: str) -> str | None:
        try:
            return socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror, TimeoutError):
            return None

    @staticmethod
    def _gateway_for(interface: str) -> str | None:
        executable = shutil.which("ip")
        if not executable:
            return None
        result = subprocess.run([executable, "-4", "route", "show", "default", "dev", interface],
                                capture_output=True, text=True, check=False)
        match = re.search(r"\bvia\s+((?:\d{1,3}\.){3}\d{1,3})", result.stdout)
        if match:
            return match.group(1)
        return None

    @staticmethod
    def _neighbour_table(interface: str) -> dict[str, str]:
        commands = []
        if shutil.which("ip"):
            commands.append(["ip", "neigh", "show", "dev", interface])
        if shutil.which("arp"):
            commands.append(["arp", "-an"])
        for command in commands:
            result = subprocess.run(command, capture_output=True, text=True, check=False)
            if result.returncode:
                continue
            found = {}
            for line in result.stdout.splitlines():
                mac = MAC_PATTERN.search(line)
                ip = re.search(r"\(?((?:\d{1,3}\.){3}\d{1,3})\)?", line)
                if mac and ip:
                    found[ip.group(1)] = mac.group(1).lower()
            return found
        return {}

    def _vendor(self, mac: str | None) -> str | None:
        if not mac:
            return None
        cached = self.store.get_vendor(mac)
        if cached:
            return cached
        if not self.vendor_lookup:
            return None
        try:
            response = requests.get(f"https://api.macvendors.com/{mac}", timeout=2)
            if response.ok and response.text.strip():
                vendor = response.text.strip()[:200]
                self.store.set_vendor(mac, vendor)
                return vendor
        except requests.RequestException:
            LOG.info("Vendor lookup failed for %s", mac)
        return None


def validate_mac(value: str) -> str:
    if not MAC_PATTERN.fullmatch(value.strip()):
        raise ScanError("Invalid MAC address. Use aa:bb:cc:dd:ee:ff format.")
    return value.strip().lower()


def validate_nickname(value: str) -> str:
    value = value.strip()
    if not value or len(value) > 80:
        raise ScanError("Nickname must contain between 1 and 80 characters.")
    return value
