"""High-level scan orchestration."""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor

from app.models import ScanResult
from app.scanners.certificate import CertificateScanner
from app.scanners.network import NetworkScanner
from app.scanners.scoring import ScoreCalculator
from app.scanners.tls import TLSScanner
from app.scanners.web import WebScanner
from app.utils import normalize_target

LOGGER = logging.getLogger(__name__)


class WebsiteSecurityScanner:
    """Coordinate the individual scanner modules."""

    def __init__(self, timeout: float = 6.0) -> None:
        self.certificate_scanner = CertificateScanner(timeout)
        self.tls_scanner = TLSScanner(timeout)
        self.web_scanner = WebScanner(timeout + 2)
        self.network_scanner = NetworkScanner(timeout)
        self.score_calculator = ScoreCalculator()

    def scan(self, raw_target: str) -> ScanResult:
        """Run a complete scan and return a structured result."""

        normalized_url, domain, original = normalize_target(raw_target)
        result = ScanResult(input_url=original, domain=domain, normalized_url=normalized_url)
        LOGGER.info("Scan started for %s", domain)

        with ThreadPoolExecutor(max_workers=6) as executor:
            cert_future = executor.submit(self.certificate_scanner.scan, domain)
            tls_future = executor.submit(self.tls_scanner.scan, domain)
            web_future = executor.submit(self.web_scanner.scan, normalized_url, domain)
            dns_future = executor.submit(self.network_scanner.dns_info, domain)
            whois_future = executor.submit(self.network_scanner.whois_info, domain)
            ports_future = executor.submit(self.network_scanner.port_statuses, domain)

            https_enabled, cert, cert_findings, cert_errors = cert_future.result()
            result.https_enabled = https_enabled
            result.certificate = cert
            result.findings.extend(cert_findings)
            result.errors.extend(cert_errors)

            tls_versions, cipher, tls_findings, tls_errors = tls_future.result()
            result.tls_versions = tls_versions
            result.cipher = cipher
            result.findings.extend(tls_findings)
            result.errors.extend(tls_errors)

            headers, redirect, hsts, mixed, web_findings, web_errors = web_future.result()
            result.headers = headers
            result.redirect = redirect
            result.hsts = hsts
            result.mixed_content = mixed
            result.findings.extend(web_findings)
            result.errors.extend(web_errors)

            result.dns, dns_errors = dns_future.result()
            result.errors.extend(dns_errors)

            result.whois, whois_errors = whois_future.result()
            result.errors.extend(whois_errors)

            result.ports, port_errors = ports_future.result()
            result.errors.extend(port_errors)

        result.geoip, geoip_errors = self.network_scanner.geoip_info(result.dns.ipv4[0] if result.dns.ipv4 else None)
        result.errors.extend(geoip_errors)

        self.score_calculator.apply(result)
        LOGGER.info("Scan finished for %s with score %s", domain, result.score.total)
        return result

