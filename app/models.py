"""Shared data models used by the scanner, GUI, history, and exporters."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any


@dataclass(slots=True)
class Finding:
    """A security issue or informational note discovered during a scan."""

    title: str
    severity: str
    description: str
    recommendation: str = ""


@dataclass(slots=True)
class CertificateInfo:
    """Parsed X.509 certificate metadata."""

    common_name: str = "Unknown"
    organization: str = "Unknown"
    country: str = "Unknown"
    issuer: str = "Unknown"
    valid_from: str = "Unknown"
    valid_until: str = "Unknown"
    days_remaining: int | None = None
    signature_algorithm: str = "Unknown"
    public_key_size: int | None = None
    san_domains: list[str] = field(default_factory=list)
    self_signed: bool = False
    trusted: bool = False
    hostname_valid: bool = False
    ocsp_urls: list[str] = field(default_factory=list)
    chain: list[str] = field(default_factory=list)


@dataclass(slots=True)
class TLSVersionResult:
    """Support status for one TLS/SSL protocol version."""

    name: str
    supported: bool
    secure: bool
    error: str = ""


@dataclass(slots=True)
class CipherInfo:
    """Information about the negotiated cipher suite."""

    name: str = "Unknown"
    protocol: str = "Unknown"
    bits: int | None = None
    encryption: str = "Unknown"
    key_exchange: str = "Unknown"
    forward_secrecy: bool = False
    strength: str = "Unknown"
    weak_reasons: list[str] = field(default_factory=list)


@dataclass(slots=True)
class HeaderResult:
    """HTTP security header status and educational explanation."""

    name: str
    present: bool
    value: str = ""
    why_it_matters: str = ""


@dataclass(slots=True)
class RedirectInfo:
    """HTTP to HTTPS redirect analysis."""

    redirects_to_https: bool = False
    permanent_redirect: bool = False
    temporary_redirect: bool = False
    loop_detected: bool = False
    chain: list[str] = field(default_factory=list)
    status_codes: list[int] = field(default_factory=list)


@dataclass(slots=True)
class HSTSInfo:
    """Strict-Transport-Security policy analysis."""

    enabled: bool = False
    max_age: int | None = None
    include_subdomains: bool = False
    preload: bool = False


@dataclass(slots=True)
class MixedContentInfo:
    """HTTP assets discovered on an HTTPS page."""

    http_images: list[str] = field(default_factory=list)
    http_css: list[str] = field(default_factory=list)
    http_javascript: list[str] = field(default_factory=list)
    http_fonts: list[str] = field(default_factory=list)
    http_ajax: list[str] = field(default_factory=list)


@dataclass(slots=True)
class DNSInfo:
    """Best-effort DNS information."""

    ipv4: list[str] = field(default_factory=list)
    ipv6: list[str] = field(default_factory=list)
    nameservers: list[str] = field(default_factory=list)
    mx: list[str] = field(default_factory=list)
    caa: list[str] = field(default_factory=list)
    dnssec: str = "Unknown"


@dataclass(slots=True)
class WhoisInfo:
    """WHOIS registration information."""

    registrar: str = "Unknown"
    registration_date: str = "Unknown"
    expiration_date: str = "Unknown"
    updated_date: str = "Unknown"


@dataclass(slots=True)
class GeoIPInfo:
    """IP geolocation information."""

    country: str = "Unknown"
    city: str = "Unknown"
    isp: str = "Unknown"
    hosting_provider: str = "Unknown"


@dataclass(slots=True)
class PortStatus:
    """TCP port reachability."""

    port: int
    status: str


@dataclass(slots=True)
class ScoreBreakdown:
    """Point allocation for the final HTTPS score."""

    certificate: int = 0
    tls: int = 0
    headers: int = 0
    redirect: int = 0
    cipher: int = 0
    hsts: int = 0
    ocsp: int = 0

    @property
    def total(self) -> int:
        return sum(asdict(self).values())


@dataclass(slots=True)
class ScanResult:
    """Complete scan output."""

    input_url: str
    domain: str
    normalized_url: str
    scanned_at: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))
    https_enabled: bool = False
    certificate: CertificateInfo = field(default_factory=CertificateInfo)
    tls_versions: list[TLSVersionResult] = field(default_factory=list)
    cipher: CipherInfo = field(default_factory=CipherInfo)
    headers: list[HeaderResult] = field(default_factory=list)
    redirect: RedirectInfo = field(default_factory=RedirectInfo)
    hsts: HSTSInfo = field(default_factory=HSTSInfo)
    mixed_content: MixedContentInfo = field(default_factory=MixedContentInfo)
    dns: DNSInfo = field(default_factory=DNSInfo)
    whois: WhoisInfo = field(default_factory=WhoisInfo)
    geoip: GeoIPInfo = field(default_factory=GeoIPInfo)
    ports: list[PortStatus] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    score: ScoreBreakdown = field(default_factory=ScoreBreakdown)
    overall_rating: str = "Unknown"
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Return a plain dictionary that can be serialized to JSON."""

        return asdict(self)

