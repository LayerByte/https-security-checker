"""Score and recommendation generation."""

from __future__ import annotations

from app.models import Finding, ScanResult, ScoreBreakdown


class ScoreCalculator:
    """Translate scanner output into a simple 100-point grade."""

    def apply(self, result: ScanResult) -> None:
        """Mutate the result with score, rating, and recommendations."""

        result.score = ScoreBreakdown(
            certificate=self._certificate_points(result),
            tls=self._tls_points(result),
            headers=self._header_points(result),
            redirect=self._redirect_points(result),
            cipher=self._cipher_points(result),
            hsts=self._hsts_points(result),
            ocsp=self._ocsp_points(result),
        )
        result.overall_rating = self._rating(result.score.total)
        result.recommendations = self._recommendations(result.findings)

    def _certificate_points(self, result: ScanResult) -> int:
        points = 20
        for finding in result.findings:
            if finding.title in {"HTTPS not available", "Expired certificate"}:
                points -= 20
            elif finding.title in {"Self-signed certificate", "Invalid hostname", "Untrusted issuer", "MD5 certificate signature", "SHA1 certificate signature", "Weak public key"}:
                points -= 8
            elif "Certificate" in finding.title:
                points -= 3
        return max(points, 0)

    def _tls_points(self, result: ScanResult) -> int:
        points = 20
        if any(item.supported and not item.secure for item in result.tls_versions):
            points -= 12
        if not any(item.name == "TLS 1.2" and item.supported for item in result.tls_versions):
            points -= 8
        if not any(item.name == "TLS 1.3" and item.supported for item in result.tls_versions):
            points -= 3
        return max(points, 0)

    def _header_points(self, result: ScanResult) -> int:
        if not result.headers:
            return 0
        present = sum(1 for header in result.headers if header.present)
        return round((present / len(result.headers)) * 20)

    def _redirect_points(self, result: ScanResult) -> int:
        if result.redirect.loop_detected:
            return 0
        if result.redirect.redirects_to_https and result.redirect.permanent_redirect:
            return 10
        if result.redirect.redirects_to_https:
            return 7
        return 0

    def _cipher_points(self, result: ScanResult) -> int:
        if result.cipher.name == "Unknown":
            return 0
        points = 15
        if result.cipher.weak_reasons:
            points -= 12
        if not result.cipher.forward_secrecy:
            points -= 3
        return max(points, 0)

    def _hsts_points(self, result: ScanResult) -> int:
        if not result.hsts.enabled:
            return 0
        points = 7
        if result.hsts.max_age and result.hsts.max_age >= 31_536_000:
            points += 1
        if result.hsts.include_subdomains:
            points += 1
        if result.hsts.preload:
            points += 1
        return min(points, 10)

    def _ocsp_points(self, result: ScanResult) -> int:
        return 5 if result.certificate.ocsp_urls else 0

    def _rating(self, total: int) -> str:
        if total >= 90:
            return "Excellent"
        if total >= 75:
            return "Good"
        if total >= 55:
            return "Average"
        if total >= 35:
            return "Poor"
        return "Critical"

    def _recommendations(self, findings: list[Finding]) -> list[str]:
        """Deduplicate finding recommendations in severity order."""

        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        recommendations: list[str] = []
        for finding in sorted(findings, key=lambda item: severity_order.get(item.severity, 9)):
            if finding.recommendation and finding.recommendation not in recommendations:
                recommendations.append(finding.recommendation)
        return recommendations or ["No urgent fixes detected. Keep monitoring certificates, TLS policy, and security headers."]

