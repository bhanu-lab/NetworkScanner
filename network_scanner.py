"""Reliable, CIDR-aware discovery of devices on a local IPv4 network."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
import ipaddress
import logging
import math
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
IPV4_PATTERN = re.compile(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)")
MAC_PATTERN = re.compile(
    r"(?i)(?<![0-9a-f])([0-9a-f]{2}([:-])(?:[0-9a-f]{2}\2){4}[0-9a-f]{2})(?![0-9a-f])"
)


class ScanError(RuntimeError):
    """A user-actionable scan failure."""


@dataclass(frozen=True)
class Interface:
    name: str
    address: str
    netmask: str
    network: str
    is_default: bool = False

    @property
    def identifier(self) -> str:
        return f"{self.name}@{self.address}"

    def to_dict(self) -> dict:
        return {**asdict(self), "id": self.identifier}


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
        try:
            import psutil
        except ImportError as error:
            raise ScanError(
                "The psutil package is required to inspect network interfaces. "
                "Install the application requirements and try again."
            ) from error

        try:
            addresses = psutil.net_if_addrs()
            stats = psutil.net_if_stats()
        except Exception as error:
            raise ScanError("Unable to read network interfaces from the operating system.") from error

        default_ip = self._default_local_ip()
        result = []
        seen = set()
        for name, assigned_addresses in addresses.items():
            state = stats.get(name)
            if state is not None and not state.isup:
                continue
            for assigned in assigned_addresses:
                if assigned.family != socket.AF_INET or not assigned.address or not assigned.netmask:
                    continue
                try:
                    configured = ipaddress.ip_interface(f"{assigned.address}/{assigned.netmask}")
                except ValueError:
                    continue
                if configured.ip.is_loopback or configured.ip.is_unspecified:
                    continue
                identity = (name, str(configured.ip), str(configured.network))
                if identity in seen:
                    continue
                seen.add(identity)
                result.append(Interface(
                    name=name,
                    address=str(configured.ip),
                    netmask=str(configured.netmask),
                    network=str(configured.network),
                    is_default=str(configured.ip) == default_ip,
                ))
        return sorted(result, key=lambda item: (not item.is_default, item.name, item.address))

    @staticmethod
    def _default_local_ip() -> str | None:
        """Return the IPv4 address selected by the OS default route without sending data."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
                probe.connect(("192.0.2.1", 9))
                address = probe.getsockname()[0]
                return address if address != "0.0.0.0" else None
        except OSError:
            return None

    def interface(self, selector: str) -> Interface:
        available = self.interfaces()
        match = next((item for item in available if item.identifier == selector), None)
        if match is None:
            match = next((item for item in available if item.name == selector), None)
        if not match:
            raise ScanError(f"Interface '{selector}' has no usable IPv4 address.")
        return match

    def scan(self, interface_selector: str) -> tuple[list[dict], float]:
        interface = self.interface(interface_selector)
        network = ipaddress.ip_network(interface.network)
        host_count = network.num_addresses if network.prefixlen >= 31 else network.num_addresses - 2
        if host_count > self.max_hosts:
            raise ScanError(f"Network {network} contains {host_count} hosts; limit is {self.max_hosts}. "
                            "Set NETSCAN_MAX_HOSTS if this is intentional.")
        started = time.monotonic()
        gateway = self._gateway_for(interface.name, interface.address)
        live = self._discover(network.hosts(), interface.name, interface.address)
        neighbours = self._neighbour_table(interface.name, interface.address)
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
            futures = {pool.submit(self._ping, str(host), interface, local_ip): str(host)
                       for host in hosts if str(host) != local_ip}
            for future in as_completed(futures):
                try:
                    if future.result():
                        live.add(futures[future])
                except OSError as error:
                    raise ScanError(str(error)) from error
        return live

    def _ping(self, ip: str, interface: str, source_ip: str) -> bool:
        executable = shutil.which("ping")
        if not executable:
            raise OSError("The 'ping' command is required but was not found.")
        system = platform.system()
        timeout_ms = max(1, math.ceil(self.timeout * 1000))
        if system == "Windows":
            command = [executable, "-n", "1", "-w", str(timeout_ms),
                       "-S", source_ip, ip]
        elif system == "Darwin":
            command = [executable, "-n", "-c", "1", "-W", str(timeout_ms),
                       "-S", source_ip, ip]
        elif system == "Linux":
            command = [executable, "-n", "-c", "1", "-W",
                       str(max(1, math.ceil(self.timeout))), "-I", interface, ip]
        else:
            raise OSError(f"Unsupported operating system: {system or 'unknown'}")
        options = {
            "stdout": subprocess.DEVNULL,
            "stderr": subprocess.DEVNULL,
            "check": False,
            "timeout": self.timeout + 1,
        }
        if system == "Windows":
            options["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        try:
            return subprocess.run(command, **options).returncode == 0
        except subprocess.TimeoutExpired:
            return False

    @staticmethod
    def _hostname(ip: str) -> str | None:
        try:
            return socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror, TimeoutError):
            return None

    @staticmethod
    def _run_command(command: list[str]) -> subprocess.CompletedProcess[str] | None:
        options = {"capture_output": True, "text": True, "check": False, "timeout": 3}
        if platform.system() == "Windows":
            options["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        try:
            return subprocess.run(command, **options)
        except (OSError, subprocess.TimeoutExpired):
            return None

    @staticmethod
    def _valid_ipv4(value: str) -> str | None:
        try:
            address = ipaddress.ip_address(value)
            return str(address) if isinstance(address, ipaddress.IPv4Address) else None
        except ValueError:
            return None

    @classmethod
    def _gateway_for(cls, interface: str, source_ip: str) -> str | None:
        system = platform.system()
        if system == "Linux" and (executable := shutil.which("ip")):
            command = [executable, "-4", "route", "show", "default", "dev", interface]
        elif system == "Darwin" and (executable := shutil.which("route")):
            command = [executable, "-n", "get", "default"]
        elif system == "Windows" and (executable := shutil.which("route")):
            command = [executable, "print", "-4"]
        else:
            return None

        result = cls._run_command(command)
        if not result or result.returncode:
            return None
        if system == "Linux":
            match = re.search(r"\bvia\s+((?:\d{1,3}\.){3}\d{1,3})", result.stdout)
            return cls._valid_ipv4(match.group(1)) if match else None
        if system == "Darwin":
            route_interface = re.search(r"^\s*interface:\s*(\S+)", result.stdout, re.MULTILINE)
            if route_interface and route_interface.group(1) != interface:
                return None
            match = re.search(r"^\s*gateway:\s*((?:\d{1,3}\.){3}\d{1,3})",
                              result.stdout, re.MULTILINE)
            return cls._valid_ipv4(match.group(1)) if match else None

        candidates = []
        route_line = re.compile(
            r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+"
            r"((?:\d{1,3}\.){3}\d{1,3})\s+"
            r"((?:\d{1,3}\.){3}\d{1,3})\s+(\d+)\s*$"
        )
        for line in result.stdout.splitlines():
            match = route_line.match(line)
            if not match or match.group(2) != source_ip:
                continue
            gateway = cls._valid_ipv4(match.group(1))
            if gateway:
                candidates.append((int(match.group(3)), gateway))
        return min(candidates)[1] if candidates else None

    @classmethod
    def _neighbour_table(cls, interface: str, source_ip: str) -> dict[str, str]:
        system = platform.system()
        commands: list[list[str]] = []
        arp = shutil.which("arp")
        if system == "Linux" and (executable := shutil.which("ip")):
            commands.append([executable, "neigh", "show", "dev", interface])
        if system == "Windows" and arp:
            commands.append([arp, "-a", "-N", source_ip])
        elif arp:
            commands.append([arp, "-an"])

        for command in commands:
            result = cls._run_command(command)
            if not result or result.returncode:
                continue
            found = {}
            for line in result.stdout.splitlines():
                if system == "Darwin":
                    line_interface = re.search(r"\bon\s+(\S+)", line)
                    if line_interface and line_interface.group(1) != interface:
                        continue
                mac = MAC_PATTERN.search(line)
                if not mac:
                    continue
                ip = None
                for candidate in IPV4_PATTERN.findall(line):
                    if ip := cls._valid_ipv4(candidate):
                        break
                if ip:
                    found[ip] = mac.group(1).replace("-", ":").lower()
            if found:
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
    match = MAC_PATTERN.fullmatch(value.strip())
    if not match:
        raise ScanError("Invalid MAC address. Use aa:bb:cc:dd:ee:ff format.")
    return match.group(1).replace("-", ":").lower()


def validate_nickname(value: str) -> str:
    value = value.strip()
    if not value or len(value) > 80:
        raise ScanError("Nickname must contain between 1 and 80 characters.")
    return value
