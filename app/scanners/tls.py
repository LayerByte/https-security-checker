"""TLS version and cipher probing."""

from __future__ import annotations

import logging
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed

from app.models import CipherInfo, Finding, TLSVersionResult

LOGGER = logging.getLogger(__name__)


class TLSScanner:
    """Probe supported TLS protocol versions and the negotiated cipher."""

    def __init__(self, timeout: float = 5.0) -> None:
        self.timeout = timeout

    def scan(self, domain: str, port: int = 443) -> tuple[list[TLSVersionResult], CipherInfo, list[Finding], list[str]]:
        """Run TLS protocol and cipher checks."""

        errors: list[str] = []
        versions = self._scan_versions(domain, port)
        cipher = self._scan_cipher(domain, port, errors)
        findings = self._findings(versions, cipher)
        return versions, cipher, findings, errors

    def _scan_versions(self, domain: str, port: int) -> list[TLSVersionResult]:
        """Check TLS versions concurrently."""

        checks: list[tuple[str, object | None, bool]] = [
            ("SSLv2", None, False),
            ("SSLv3", None, False),
            ("TLS 1.0", getattr(ssl.TLSVersion, "TLSv1", None), False),
            ("TLS 1.1", getattr(ssl.TLSVersion, "TLSv1_1", None), False),
            ("TLS 1.2", getattr(ssl.TLSVersion, "TLSv1_2", None), True),
            ("TLS 1.3", getattr(ssl.TLSVersion, "TLSv1_3", None), True),
        ]

        results: dict[str, TLSVersionResult] = {}
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = {
                executor.submit(self._try_version, domain, port, name, version, secure): name
                for name, version, secure in checks
            }
            for future in as_completed(futures):
                result = future.result()
                results[result.name] = result

        return [results[name] for name, _, _ in checks]

    def _try_version(self, domain: str, port: int, name: str, version: object | None, secure: bool) -> TLSVersionResult:
        """Attempt one TLS version."""

        if version is None:
            return TLSVersionResult(name, False, secure, "Disabled by modern Python/OpenSSL clients.")

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = version
        context.maximum_version = version
        try:
            context.set_ciphers("DEFAULT:@SECLEVEL=0")
        except ssl.SSLError:
            pass

        try:
            with socket.create_connection((domain, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain):
                    return TLSVersionResult(name, True, secure)
        except Exception as exc:
            return TLSVersionResult(name, False, secure, str(exc))

    def _scan_cipher(self, domain: str, port: int, errors: list[str]) -> CipherInfo:
        """Capture the default negotiated cipher suite."""

        context = ssl.create_default_context()
        try:
            with socket.create_connection((domain, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as tls_sock:
                    name, protocol, bits = tls_sock.cipher()
        except Exception as exc:
            LOGGER.warning("Cipher scan failed for %s: %s", domain, exc)
            errors.append(f"Cipher scan failed: {exc}")
            return CipherInfo()

        weak_reasons = self._weak_cipher_reasons(name, bits)
        forward_secrecy = any(token in name.upper() for token in ("ECDHE", "DHE"))
        return CipherInfo(
            name=name,
            protocol=protocol,
            bits=bits,
            encryption=self._infer_encryption(name),
            key_exchange=self._infer_key_exchange(name),
            forward_secrecy=forward_secrecy,
            strength="Weak" if weak_reasons else "Strong",
            weak_reasons=weak_reasons,
        )

    def _weak_cipher_reasons(self, name: str, bits: int | None) -> list[str]:
        """Detect obsolete or intentionally insecure cipher properties."""

        upper_name = name.upper()
        reasons = []
        for token in ("RC4", "3DES", "DES-CBC3", "NULL", "EXPORT", "ADH", "AECDH", "ANON"):
            if token in upper_name:
                reasons.append(token)
        if bits is not None and bits < 128:
            reasons.append("Less than 128-bit encryption")
        return reasons

    def _infer_encryption(self, name: str) -> str:
        """Infer the bulk encryption algorithm from a cipher name."""

        upper_name = name.upper()
        for token in ("CHACHA20", "AES_256", "AES256", "AES_128", "AES128", "3DES", "RC4", "NULL"):
            if token in upper_name:
                return token.replace("_", "-")
        return "Unknown"

    def _infer_key_exchange(self, name: str) -> str:
        """Infer key exchange from a cipher name."""

        upper_name = name.upper()
        for token in ("ECDHE", "DHE", "RSA", "PSK", "ECDH", "DH"):
            if token in upper_name:
                return token
        return "TLS 1.3 / Unknown"

    def _findings(self, versions: list[TLSVersionResult], cipher: CipherInfo) -> list[Finding]:
        """Generate TLS and cipher findings."""

        findings: list[Finding] = []
        for version in versions:
            if version.supported and not version.secure:
                findings.append(
                    Finding(
                        f"{version.name} enabled",
                        "HIGH",
                        f"{version.name} is obsolete and exposes clients to downgrade and protocol attacks.",
                        f"Disable {version.name} on the server.",
                    )
                )

        if not any(item.supported and item.name == "TLS 1.3" for item in versions):
            findings.append(Finding("TLS 1.3 not supported", "LOW", "The server did not negotiate TLS 1.3 during probing.", "Enable TLS 1.3 where platform support allows it."))

        if cipher.weak_reasons:
            findings.append(
                Finding(
                    "Weak cipher detected",
                    "HIGH",
                    f"The negotiated cipher has weak properties: {', '.join(cipher.weak_reasons)}.",
                    "Disable weak cipher suites and prefer AEAD suites such as AES-GCM or ChaCha20-Poly1305.",
                )
            )
        elif cipher.name != "Unknown" and not cipher.forward_secrecy:
            findings.append(Finding("No forward secrecy", "MEDIUM", "The negotiated cipher does not advertise ECDHE/DHE.", "Prefer ECDHE or TLS 1.3 cipher suites."))

        return findings

