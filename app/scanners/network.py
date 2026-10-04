"""DNS, WHOIS, GeoIP, and port checks."""

from __future__ import annotations

import logging
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

from app.models import DNSInfo, GeoIPInfo, PortStatus, WhoisInfo
from app.utils import flatten_date

LOGGER = logging.getLogger(__name__)

try:
    import dns.resolver
except ImportError:  # pragma: no cover - optional dependency
    dns = None

try:
    import whois
except ImportError:  # pragma: no cover - optional dependency
    whois = None


class NetworkScanner:
    """Collect supporting network intelligence."""

    def __init__(self, timeout: float = 4.0) -> None:
        self.timeout = timeout

    def dns_info(self, domain: str) -> tuple[DNSInfo, list[str]]:
        """Resolve IP addresses and optional DNS record types."""

        errors: list[str] = []
        info = DNSInfo()

        try:
            for family, _, _, _, sockaddr in socket.getaddrinfo(domain, None):
                if family == socket.AF_INET:
                    info.ipv4.append(sockaddr[0])
                elif family == socket.AF_INET6:
                    info.ipv6.append(sockaddr[0])
            info.ipv4 = sorted(set(info.ipv4))
            info.ipv6 = sorted(set(info.ipv6))
        except Exception as exc:
            errors.append(f"DNS address lookup failed: {exc}")

        if dns is None:
            errors.append("dnspython is not installed; advanced DNS records skipped.")
            return info, errors

        resolver = dns.resolver.Resolver()
        resolver.lifetime = self.timeout
        resolver.timeout = self.timeout
        for record_type, target in (("NS", info.nameservers), ("MX", info.mx), ("CAA", info.caa)):
            try:
                answers = resolver.resolve(domain, record_type)
                target.extend(sorted(str(answer).rstrip(".") for answer in answers))
            except Exception:
                continue

        try:
            answers = resolver.resolve(domain, "DNSKEY")
            info.dnssec = "Enabled" if answers else "Unknown"
        except Exception:
            info.dnssec = "Not detected"

        return info, errors

    def whois_info(self, domain: str) -> tuple[WhoisInfo, list[str]]:
        """Return WHOIS data when python-whois is installed."""

        if whois is None:
            return WhoisInfo(), ["python-whois is not installed; WHOIS skipped."]
        try:
            data = whois.whois(domain)
            return (
                WhoisInfo(
                    registrar=flatten_date(getattr(data, "registrar", None) or data.get("registrar")),
                    registration_date=flatten_date(getattr(data, "creation_date", None) or data.get("creation_date")),
                    expiration_date=flatten_date(getattr(data, "expiration_date", None) or data.get("expiration_date")),
                    updated_date=flatten_date(getattr(data, "updated_date", None) or data.get("updated_date")),
                ),
                [],
            )
        except Exception as exc:
            return WhoisInfo(), [f"WHOIS lookup failed: {exc}"]

    def geoip_info(self, ip_address: str | None) -> tuple[GeoIPInfo, list[str]]:
        """Use a public GeoIP API when an address is available."""

        if not ip_address:
            return GeoIPInfo(), ["GeoIP skipped because no IPv4 address was resolved."]
        try:
            response = requests.get(
                f"http://ip-api.com/json/{ip_address}",
                params={"fields": "status,country,city,isp,org,message"},
                timeout=self.timeout,
            )
            data = response.json()
            if data.get("status") != "success":
                return GeoIPInfo(), [f"GeoIP lookup failed: {data.get('message', 'unknown error')}"]
            return (
                GeoIPInfo(
                    country=data.get("country", "Unknown"),
                    city=data.get("city", "Unknown"),
                    isp=data.get("isp", "Unknown"),
                    hosting_provider=data.get("org", "Unknown"),
                ),
                [],
            )
        except Exception as exc:
            return GeoIPInfo(), [f"GeoIP lookup failed: {exc}"]

    def port_statuses(self, domain: str, ports: list[int] | None = None) -> tuple[list[PortStatus], list[str]]:
        """Check common web ports concurrently."""

        ports = ports or [443, 80, 8443]
        statuses: list[PortStatus] = []
        errors: list[str] = []

        with ThreadPoolExecutor(max_workers=len(ports)) as executor:
            futures = {executor.submit(self._check_port, domain, port): port for port in ports}
            for future in as_completed(futures):
                try:
                    statuses.append(future.result())
                except Exception as exc:
                    errors.append(f"Port check failed: {exc}")

        statuses.sort(key=lambda item: item.port)
        return statuses, errors

    def _check_port(self, domain: str, port: int) -> PortStatus:
        """Return Open, Closed, or Filtered-ish status based on connect_ex."""

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            result = sock.connect_ex((domain, port))
            if result == 0:
                return PortStatus(port, "Open")
            if result in {10061, 111, 61}:
                return PortStatus(port, "Closed")
            return PortStatus(port, "Filtered")
        finally:
            sock.close()

