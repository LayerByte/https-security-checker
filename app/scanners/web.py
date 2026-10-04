"""HTTP headers, redirects, HSTS, and mixed-content checks."""

from __future__ import annotations

import logging
import re
from urllib.parse import urlparse

import requests

from app.models import Finding, HeaderResult, HSTSInfo, MixedContentInfo, RedirectInfo
from app.utils import limit_list

LOGGER = logging.getLogger(__name__)


HEADER_EXPLANATIONS = {
    "Strict-Transport-Security": "Forces browsers to use HTTPS and helps block SSL stripping attacks.",
    "Content-Security-Policy": "Limits where scripts, styles, frames, and other resources may load from.",
    "X-Frame-Options": "Reduces clickjacking risk by controlling whether the page can be framed.",
    "X-Content-Type-Options": "Prevents MIME sniffing that can turn uploads or assets into executable content.",
    "Referrer-Policy": "Controls how much URL/referrer data leaks to other sites.",
    "Permissions-Policy": "Restricts browser APIs such as camera, microphone, geolocation, and sensors.",
    "Cross-Origin-Opener-Policy": "Isolates browsing contexts and reduces cross-origin data exposure.",
    "Cross-Origin-Embedder-Policy": "Controls cross-origin resource embedding for stronger isolation.",
    "Cross-Origin-Resource-Policy": "Tells browsers who may load the resource across origins.",
}


class WebScanner:
    """Analyze HTTP behavior around the HTTPS endpoint."""

    def __init__(self, timeout: float = 8.0) -> None:
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "HTTPS-Security-Checker/1.0"})

    def scan(self, normalized_url: str, domain: str) -> tuple[list[HeaderResult], RedirectInfo, HSTSInfo, MixedContentInfo, list[Finding], list[str]]:
        """Run web-layer checks."""

        errors: list[str] = []
        findings: list[Finding] = []
        headers: list[HeaderResult] = []
        redirect = RedirectInfo()
        hsts = HSTSInfo()
        mixed = MixedContentInfo()

        try:
            response = self.session.get(normalized_url, timeout=self.timeout, allow_redirects=True, verify=True)
            headers = self._security_headers(response.headers)
            hsts = self._parse_hsts(response.headers.get("Strict-Transport-Security", ""))
            mixed = self._mixed_content(response.text)
        except Exception as exc:
            LOGGER.warning("HTTPS page fetch failed for %s: %s", domain, exc)
            errors.append(f"HTTPS page fetch failed: {exc}")

        try:
            redirect = self._redirect_check(domain)
        except Exception as exc:
            LOGGER.warning("Redirect check failed for %s: %s", domain, exc)
            errors.append(f"Redirect check failed: {exc}")

        findings.extend(self._header_findings(headers))
        findings.extend(self._hsts_findings(hsts))
        findings.extend(self._mixed_findings(mixed))
        findings.extend(self._redirect_findings(redirect))
        return headers, redirect, hsts, mixed, findings, errors

    def _security_headers(self, response_headers: requests.structures.CaseInsensitiveDict) -> list[HeaderResult]:
        """Return status for each required security header."""

        return [
            HeaderResult(
                name=name,
                present=name in response_headers,
                value=response_headers.get(name, ""),
                why_it_matters=why,
            )
            for name, why in HEADER_EXPLANATIONS.items()
        ]

    def _parse_hsts(self, value: str) -> HSTSInfo:
        """Parse Strict-Transport-Security directives."""

        if not value:
            return HSTSInfo()

        max_age = None
        match = re.search(r"max-age\s*=\s*(\d+)", value, re.IGNORECASE)
        if match:
            max_age = int(match.group(1))

        return HSTSInfo(
            enabled=True,
            max_age=max_age,
            include_subdomains="includesubdomains" in value.lower(),
            preload="preload" in value.lower(),
        )

    def _redirect_check(self, domain: str) -> RedirectInfo:
        """Check whether plain HTTP redirects to HTTPS."""

        visited = set()
        chain: list[str] = []
        codes: list[int] = []
        current = f"http://{domain}"

        for _ in range(10):
            if current in visited:
                return RedirectInfo(loop_detected=True, chain=chain, status_codes=codes)
            visited.add(current)

            response = self.session.get(current, timeout=self.timeout, allow_redirects=False, verify=False)
            chain.append(current)
            codes.append(response.status_code)
            location = response.headers.get("Location")
            if not location or response.status_code not in range(300, 400):
                final_url = response.url
                return RedirectInfo(
                    redirects_to_https=final_url.startswith("https://") or any(item.startswith("https://") for item in chain),
                    permanent_redirect=any(code in {301, 308} for code in codes),
                    temporary_redirect=any(code in {302, 303, 307} for code in codes),
                    chain=chain,
                    status_codes=codes,
                )

            current = requests.compat.urljoin(current, location)
            if urlparse(current).scheme == "https":
                chain.append(current)
                return RedirectInfo(
                    redirects_to_https=True,
                    permanent_redirect=any(code in {301, 308} for code in codes),
                    temporary_redirect=any(code in {302, 303, 307} for code in codes),
                    chain=chain,
                    status_codes=codes,
                )

        return RedirectInfo(loop_detected=True, chain=chain, status_codes=codes)

    def _mixed_content(self, html: str) -> MixedContentInfo:
        """Detect insecure absolute HTTP assets in the homepage HTML."""

        found = MixedContentInfo()
        attrs = re.findall(r"""<(img|script|link|source|iframe|form|font|object|embed)[^>]+(?:src|href|action)=["'](http://[^"']+)["']""", html, re.IGNORECASE)
        for tag, url in attrs:
            tag = tag.lower()
            if tag == "img":
                found.http_images.append(url)
            elif tag == "script":
                found.http_javascript.append(url)
            elif tag == "link" and re.search(r"\.(css)(?:\?|$)", url, re.IGNORECASE):
                found.http_css.append(url)
            elif tag in {"font", "source"} and re.search(r"\.(woff2?|ttf|otf)(?:\?|$)", url, re.IGNORECASE):
                found.http_fonts.append(url)
            else:
                found.http_ajax.append(url)

        xhr_urls = re.findall(r"""(?:fetch|XMLHttpRequest|axios\.\w+)\s*\(?["'](http://[^"']+)["']""", html, re.IGNORECASE)
        found.http_ajax.extend(xhr_urls)

        found.http_images = limit_list(sorted(set(found.http_images)))
        found.http_css = limit_list(sorted(set(found.http_css)))
        found.http_javascript = limit_list(sorted(set(found.http_javascript)))
        found.http_fonts = limit_list(sorted(set(found.http_fonts)))
        found.http_ajax = limit_list(sorted(set(found.http_ajax)))
        return found

    def _header_findings(self, headers: list[HeaderResult]) -> list[Finding]:
        """Generate findings for missing security headers."""

        severity = {
            "Strict-Transport-Security": "HIGH",
            "Content-Security-Policy": "MEDIUM",
            "X-Frame-Options": "MEDIUM",
            "X-Content-Type-Options": "LOW",
            "Referrer-Policy": "LOW",
            "Permissions-Policy": "LOW",
            "Cross-Origin-Opener-Policy": "LOW",
            "Cross-Origin-Embedder-Policy": "LOW",
            "Cross-Origin-Resource-Policy": "LOW",
        }
        return [
            Finding(
                f"Missing {header.name}",
                severity.get(header.name, "LOW"),
                header.why_it_matters,
                f"Configure the {header.name} HTTP response header.",
            )
            for header in headers
            if not header.present
        ]

    def _hsts_findings(self, hsts: HSTSInfo) -> list[Finding]:
        """Generate HSTS findings."""

        findings = []
        if not hsts.enabled:
            findings.append(Finding("HSTS missing", "HIGH", "Browsers are not instructed to pin HTTPS for this host.", "Add Strict-Transport-Security with a long max-age."))
        elif hsts.max_age is not None and hsts.max_age < 15_552_000:
            findings.append(Finding("HSTS max-age too short", "MEDIUM", "The HSTS max-age is below 180 days.", "Use max-age=31536000 or higher after testing."))
        if hsts.enabled and not hsts.include_subdomains:
            findings.append(Finding("HSTS includeSubDomains missing", "LOW", "Subdomains are not protected by the HSTS policy.", "Add includeSubDomains when all subdomains support HTTPS."))
        return findings

    def _mixed_findings(self, mixed: MixedContentInfo) -> list[Finding]:
        """Generate mixed-content findings."""

        count = sum(len(items) for items in (mixed.http_images, mixed.http_css, mixed.http_javascript, mixed.http_fonts, mixed.http_ajax))
        if count == 0:
            return []
        return [
            Finding(
                "Mixed content detected",
                "HIGH",
                f"The HTTPS homepage references {count} HTTP resource(s).",
                "Load all images, scripts, styles, fonts, and AJAX endpoints over HTTPS.",
            )
        ]

    def _redirect_findings(self, redirect: RedirectInfo) -> list[Finding]:
        """Generate redirect findings."""

        findings = []
        if redirect.loop_detected:
            findings.append(Finding("Redirect loop", "HIGH", "The HTTP redirect chain appears to loop.", "Fix redirect rules and canonical host handling."))
        elif not redirect.redirects_to_https:
            findings.append(Finding("HTTP does not redirect to HTTPS", "MEDIUM", "Users can reach the site over plaintext HTTP.", "Redirect all HTTP traffic to HTTPS."))
        elif not redirect.permanent_redirect:
            findings.append(Finding("HTTP redirect is temporary", "LOW", "The site redirects to HTTPS but does not use a permanent status code.", "Use 301 or 308 redirects for HTTP to HTTPS."))
        return findings

