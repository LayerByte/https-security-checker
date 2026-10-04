"""Certificate retrieval and validation."""

from __future__ import annotations

import logging
import socket
import ssl
from datetime import datetime, timezone

from app.models import CertificateInfo, Finding

LOGGER = logging.getLogger(__name__)

try:
    import certifi
except ImportError:  # pragma: no cover - optional fallback
    certifi = None

try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
    from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID, NameOID
except ImportError:  # pragma: no cover - optional fallback
    x509 = None
    rsa = dsa = ec = None
    AuthorityInformationAccessOID = ExtensionOID = NameOID = None


class CertificateScanner:
    """Fetch and analyze the server certificate."""

    def __init__(self, timeout: float = 6.0) -> None:
        self.timeout = timeout

    def scan(self, domain: str, port: int = 443) -> tuple[bool, CertificateInfo, list[Finding], list[str]]:
        """Return HTTPS availability, certificate info, findings, and errors."""

        findings: list[Finding] = []
        errors: list[str] = []
        cert_info = CertificateInfo()
        https_enabled = False

        try:
            der_cert, dict_cert = self._fetch_certificate(domain, port)
            https_enabled = True
            cert_info = self._parse_certificate(der_cert, dict_cert)
            cert_info.chain = self._build_visual_chain(cert_info)
        except Exception as exc:
            LOGGER.warning("Certificate fetch failed for %s: %s", domain, exc)
            errors.append(f"HTTPS certificate fetch failed: {exc}")
            findings.append(
                Finding(
                    "HTTPS not available",
                    "CRITICAL",
                    "The server did not complete a TLS handshake on port 443.",
                    "Enable HTTPS with a valid certificate.",
                )
            )
            return False, cert_info, findings, errors

        trusted, hostname_valid, validation_error = self._validate_certificate(domain, port)
        cert_info.trusted = trusted
        cert_info.hostname_valid = hostname_valid
        if validation_error:
            errors.append(validation_error)

        findings.extend(self._certificate_findings(cert_info, validation_error))
        return https_enabled, cert_info, findings, errors

    def _fetch_certificate(self, domain: str, port: int) -> tuple[bytes, dict]:
        """Fetch the leaf certificate without verification so invalid certs can be inspected."""

        context = ssl._create_unverified_context()
        with socket.create_connection((domain, port), timeout=self.timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as tls_sock:
                der_cert = tls_sock.getpeercert(binary_form=True)
                dict_cert = tls_sock.getpeercert()
        if not der_cert:
            raise ssl.SSLError("Server did not provide a certificate.")
        return der_cert, dict_cert

    def _validate_certificate(self, domain: str, port: int) -> tuple[bool, bool, str]:
        """Validate the certificate against the OS/certifi trust store and hostname."""

        context = ssl.create_default_context(cafile=certifi.where() if certifi else None)
        try:
            with socket.create_connection((domain, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain):
                    return True, True, ""
        except ssl.SSLCertVerificationError as exc:
            message = str(exc)
            hostname_valid = "hostname" not in message.lower() and "not valid for" not in message.lower()
            return False, hostname_valid, f"Certificate validation failed: {message}"
        except Exception as exc:
            return False, False, f"Certificate validation failed: {exc}"

    def _parse_certificate(self, der_cert: bytes, dict_cert: dict) -> CertificateInfo:
        """Parse certificate details with cryptography when available."""

        if x509 is None:
            return self._parse_certificate_fallback(dict_cert)

        cert = x509.load_der_x509_certificate(der_cert)
        subject = cert.subject
        issuer = cert.issuer

        public_key = cert.public_key()
        key_size = getattr(public_key, "key_size", None)
        if ec is not None and isinstance(public_key, ec.EllipticCurvePublicKey):
            key_size = public_key.curve.key_size
        elif rsa is not None and isinstance(public_key, rsa.RSAPublicKey):
            key_size = public_key.key_size
        elif dsa is not None and isinstance(public_key, dsa.DSAPublicKey):
            key_size = public_key.key_size

        not_before = getattr(cert, "not_valid_before_utc", cert.not_valid_before.replace(tzinfo=timezone.utc))
        not_after = getattr(cert, "not_valid_after_utc", cert.not_valid_after.replace(tzinfo=timezone.utc))
        days_remaining = (not_after - datetime.now(timezone.utc)).days

        san_domains: list[str] = []
        try:
            san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
            san_domains = san.get_values_for_type(x509.DNSName)
        except Exception:
            san_domains = []

        ocsp_urls: list[str] = []
        try:
            aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
            ocsp_urls = [
                item.access_location.value
                for item in aia
                if item.access_method == AuthorityInformationAccessOID.OCSP
            ]
        except Exception:
            ocsp_urls = []

        sig_alg = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "Unknown"

        return CertificateInfo(
            common_name=self._first_name_attr(subject, NameOID.COMMON_NAME),
            organization=self._first_name_attr(subject, NameOID.ORGANIZATION_NAME),
            country=self._first_name_attr(subject, NameOID.COUNTRY_NAME),
            issuer=issuer.rfc4514_string(),
            valid_from=not_before.isoformat(timespec="seconds"),
            valid_until=not_after.isoformat(timespec="seconds"),
            days_remaining=days_remaining,
            signature_algorithm=sig_alg.upper(),
            public_key_size=key_size,
            san_domains=san_domains,
            self_signed=subject == issuer,
            ocsp_urls=ocsp_urls,
        )

    def _parse_certificate_fallback(self, dict_cert: dict) -> CertificateInfo:
        """Basic parser for systems without the cryptography package."""

        def find_name(section: str, key: str) -> str:
            for group in dict_cert.get(section, []):
                for item_key, item_value in group:
                    if item_key == key:
                        return item_value
            return "Unknown"

        days_remaining = None
        valid_until = dict_cert.get("notAfter", "Unknown")
        if valid_until != "Unknown":
            try:
                expires = datetime.strptime(valid_until, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                days_remaining = (expires - datetime.now(timezone.utc)).days
            except ValueError:
                days_remaining = None

        return CertificateInfo(
            common_name=find_name("subject", "commonName"),
            organization=find_name("subject", "organizationName"),
            country=find_name("subject", "countryName"),
            issuer=find_name("issuer", "commonName"),
            valid_from=dict_cert.get("notBefore", "Unknown"),
            valid_until=valid_until,
            days_remaining=days_remaining,
            san_domains=[value for kind, value in dict_cert.get("subjectAltName", []) if kind == "DNS"],
        )

    def _first_name_attr(self, name: object, oid: object) -> str:
        """Return the first X.509 name attribute for an OID."""

        attrs = name.get_attributes_for_oid(oid)
        return attrs[0].value if attrs else "Unknown"

    def _certificate_findings(self, cert: CertificateInfo, validation_error: str) -> list[Finding]:
        """Generate certificate-specific findings."""

        findings: list[Finding] = []
        days = cert.days_remaining

        if days is not None and days < 0:
            findings.append(Finding("Expired certificate", "CRITICAL", "The certificate is past its validity period.", "Renew and deploy a valid certificate."))
        elif days is not None and days <= 7:
            findings.append(Finding("Certificate expires soon", "HIGH", f"The certificate expires in {days} days.", "Renew the certificate before service disruption occurs."))
        elif days is not None and days <= 30:
            findings.append(Finding("Certificate renewal window", "MEDIUM", f"The certificate expires in {days} days.", "Schedule renewal soon."))

        if cert.self_signed:
            findings.append(Finding("Self-signed certificate", "HIGH", "The certificate issuer matches the subject.", "Use a certificate issued by a trusted public CA."))

        if not cert.hostname_valid:
            findings.append(Finding("Invalid hostname", "HIGH", "The certificate does not validate for the requested hostname.", "Issue a certificate whose SAN contains this domain."))

        if not cert.trusted:
            findings.append(Finding("Untrusted issuer", "HIGH", validation_error or "The certificate chain is not trusted.", "Install a complete certificate chain from a trusted CA."))

        sig = cert.signature_algorithm.lower()
        if "md5" in sig:
            findings.append(Finding("MD5 certificate signature", "CRITICAL", "The certificate uses the obsolete MD5 hash algorithm.", "Replace the certificate with SHA-256 or stronger."))
        elif "sha1" in sig or "sha-1" in sig:
            findings.append(Finding("SHA1 certificate signature", "HIGH", "The certificate uses SHA1, which is no longer acceptable for public TLS.", "Replace the certificate with SHA-256 or stronger."))

        if cert.public_key_size is not None and cert.public_key_size < 2048:
            findings.append(Finding("Weak public key", "HIGH", f"The public key is only {cert.public_key_size} bits.", "Use RSA 2048+ or a modern ECDSA key."))

        if not cert.ocsp_urls:
            findings.append(Finding("OCSP URL missing", "LOW", "The certificate does not advertise an OCSP responder.", "Use a CA/certificate profile that includes OCSP information."))

        return findings

    def _build_visual_chain(self, cert: CertificateInfo) -> list[str]:
        """Create a best-effort trust-chain display for the UI."""

        chain = ["Server Certificate: " + cert.common_name]
        if cert.issuer and cert.issuer != "Unknown":
            chain.append("Issuer / Intermediate CA: " + cert.issuer)
        chain.append("Root CA: System trust store" if cert.trusted else "Root CA: Not trusted or incomplete")
        return chain

