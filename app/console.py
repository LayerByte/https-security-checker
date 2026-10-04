"""Windows console interface for the HTTPS Security Checker."""

from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path

from app.models import HeaderResult, ScanResult
from app.scanners.orchestrator import WebsiteSecurityScanner
from app.storage.history import HistoryStore


ARTWORK = r"""
 ██░ ██ ▄▄▄█████▓▄▄▄█████▓ ██▓███      ▄████▄   ██░ ██ ▓█████  ▄████▄   ██ ▄█▀▓█████  ██▀███
▓██░ ██▒▓  ██▒ ▓▒▓  ██▒ ▓▒▓██░  ██▒   ▒██▀ ▀█  ▓██░ ██▒▓█   ▀ ▒██▀ ▀█   ██▄█▒ ▓█   ▀ ▓██ ▒ ██▒
▒██▀▀██░▒ ▓██░ ▒░▒ ▓██░ ▒░▓██░ ██▓▒   ▒▓█    ▄ ▒██▀▀██░▒███   ▒▓█    ▄ ▓███▄░ ▒███   ▓██ ░▄█ ▒
░▓█ ░██ ░ ▓██▓ ░ ░ ▓██▓ ░ ▒██▄█▓▒ ▒   ▒▓▓▄ ▄██▒░▓█ ░██ ▒▓█  ▄ ▒▓▓▄ ▄██▒▓██ █▄ ▒▓█  ▄ ▒██▀▀█▄
░▓█▒░██▓  ▒██▒ ░   ▒██▒ ░ ▒██▒ ░  ░   ▒ ▓███▀ ░░▓█▒░██▓░▒████▒▒ ▓███▀ ░▒██▒ █▄░▒████▒░██▓ ▒██▒
 ▒ ░░▒░▒  ▒ ░░     ▒ ░░   ▒▓▒░ ░  ░   ░ ░▒ ▒  ░ ▒ ░░▒░▒░░ ▒░ ░░ ░▒ ▒  ░▒ ▒▒ ▓▒░░ ▒░ ░░ ▒▓ ░▒▓░
 ▒ ░▒░ ░    ░        ░    ░▒ ░          ░  ▒    ▒ ░▒░ ░ ░ ░  ░  ░  ▒   ░ ░▒ ▒░ ░ ░  ░  ░▒ ░ ▒░
 ░  ░░ ░  ░        ░      ░░          ░         ░  ░░ ░   ░   ░        ░ ░░ ░    ░     ░░   ░
 ░  ░  ░                              ░ ░       ░  ░  ░   ░  ░░ ░      ░  ░      ░  ░   ░
                                      ░                       ░
"""


class ConsoleColors:
    """ANSI color constants for modern Windows terminals."""

    WHITE = "\033[97m"
    BLACK_BACKGROUND = "\033[40m"
    CYAN = "\033[96m"
    BLUE = "\033[94m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    MAGENTA = "\033[95m"
    DIM = "\033[2m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


class HTTPSCheckerConsole:
    """Interactive command-line application."""

    def __init__(self) -> None:
        self.scanner = WebsiteSecurityScanner()
        self.history = HistoryStore()
        self.current_result: ScanResult | None = None
        self._configure_console()

    def run(self) -> None:
        """Start the interactive console loop."""

        while True:
            self._clear()
            self._print_header()
            self._print_dashboard()
            self._print_menu()
            choice = input(self._prompt("Select option")).strip().lower()

            if choice in {"1", "scan", "s"}:
                self._scan_single()
            elif choice in {"2", "batch", "b"}:
                self._batch_scan()
            elif choice in {"3", "history", "h"}:
                self._show_history()
            elif choice in {"4", "clear", "c"}:
                self.current_result = None
            elif choice in {"0", "exit", "q", "quit"}:
                self._line("Goodbye.", ConsoleColors.CYAN)
                return
            else:
                self._pause("Unknown option.")

    def _configure_console(self) -> None:
        """Enable UTF-8 output and ANSI colors on Windows terminals."""

        if os.name == "nt":
            os.system("chcp 65001 > nul")
            os.system("color 0F")
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass

    def _clear(self) -> None:
        """Clear the console screen."""

        os.system("cls" if os.name == "nt" else "clear")

    def _print_header(self) -> None:
        """Print the requested artwork and app subtitle."""

        print(f"{ConsoleColors.BLACK_BACKGROUND}{ConsoleColors.WHITE}{ARTWORK}{ConsoleColors.RESET}")
        print(f"{ConsoleColors.BLACK_BACKGROUND}{ConsoleColors.WHITE}{ConsoleColors.BOLD}HTTPS/TLS Security Scanner{ConsoleColors.RESET}")
        print(f"{ConsoleColors.BLACK_BACKGROUND}{ConsoleColors.WHITE}GitHub: https://github.com/layerbyte{ConsoleColors.RESET}")
        print(f"{ConsoleColors.DIM}{'=' * 100}{ConsoleColors.RESET}")

    def _print_dashboard(self) -> None:
        """Print aggregate scan metrics."""

        data = self.history.dashboard()
        print(
            f"{ConsoleColors.GREEN}Total:{ConsoleColors.RESET} {data['total_scans']}  "
            f"{ConsoleColors.GREEN}Average:{ConsoleColors.RESET} {data['average_score']}  "
            f"{ConsoleColors.YELLOW}Weak:{ConsoleColors.RESET} {data['weak_configurations']}  "
            f"{ConsoleColors.RED}Cert Problems:{ConsoleColors.RESET} {data['expired_certificates']}  "
            f"{ConsoleColors.CYAN}Secure:{ConsoleColors.RESET} {data['secure_websites']}"
        )
        if self.current_result:
            print(
                f"{ConsoleColors.MAGENTA}Loaded result:{ConsoleColors.RESET} "
                f"{self.current_result.domain} - {self.current_result.score.total}/100 {self.current_result.overall_rating}"
            )
        print()

    def _print_menu(self) -> None:
        """Print the main menu."""

        print(f"{ConsoleColors.BOLD}Menu{ConsoleColors.RESET}")
        print("  [1] Scan website")
        print("  [2] Batch scan TXT/CSV")
        print("  [3] History and search")
        print("  [4] Clear loaded result")
        print("  [0] Exit")
        print()

    def _scan_single(self) -> None:
        """Scan one website and print the result."""

        target = input(self._prompt("Website")).strip()
        if not target:
            self._pause("No website entered.")
            return

        try:
            result = self._run_with_spinner(f"Scanning {target}", lambda: self.scanner.scan(target))
        except Exception as exc:
            self._pause(f"Scan failed: {exc}")
            return
        self.current_result = result
        self.history.save(result)
        self._clear()
        self._print_header()
        self._print_result(result)
        self._pause()

    def _batch_scan(self) -> None:
        """Scan many domains from a TXT or CSV file."""

        path_value = input(self._prompt("TXT/CSV path")).strip().strip('"')
        path = Path(path_value)
        if not path.exists():
            self._pause("File not found.")
            return

        targets = self._read_targets(path)
        if not targets:
            self._pause("No targets found in file.")
            return

        self._clear()
        self._print_header()
        self._line(f"Batch scan started: {len(targets)} target(s). Press Ctrl+C to stop after the current scan.", ConsoleColors.YELLOW)
        print()

        completed = 0
        try:
            for index, target in enumerate(targets, start=1):
                print(f"{ConsoleColors.DIM}[{index}/{len(targets)}]{ConsoleColors.RESET} {target}")
                try:
                    result = self.scanner.scan(target)
                    self.history.save(result)
                    self.current_result = result
                    completed += 1
                    print(self._score_line(result))
                except Exception as exc:
                    print(f"{ConsoleColors.RED}FAILED{ConsoleColors.RESET} {exc}")
                print()
        except KeyboardInterrupt:
            self._line("Batch interrupted by user.", ConsoleColors.YELLOW)

        self._pause(f"Batch finished. {completed} result(s) saved.")

    def _show_history(self) -> None:
        """Show history rows with optional filtering."""

        search = input(self._prompt("Search domain (blank for all)")).strip()
        rows = self.history.list(search)
        self._clear()
        self._print_header()
        self._line("History", ConsoleColors.BOLD)
        print(f"{'Date':19}  {'Domain':32}  {'Score':>5}  {'Rating':10}  {'Cert':8}  Weak")
        print("-" * 92)
        for row in rows[:40]:
            print(
                f"{row['scanned_at'][:19]:19}  "
                f"{row['domain'][:32]:32}  "
                f"{row['score']:>5}  "
                f"{row['rating'][:10]:10}  "
                f"{row['certificate_status'][:8]:8}  "
                f"{'Yes' if row['weak_configuration'] else 'No'}"
            )
        if not rows:
            print("No history rows found.")
        self._pause()

    def _print_result(self, result: ScanResult) -> None:
        """Print a complete scan result in compact console sections."""

        print(self._score_line(result))
        print(f"HTTPS Enabled: {self._yes_no(result.https_enabled)}")
        print()
        self._print_score_breakdown(result)
        self._print_certificate(result)
        self._print_tls(result)
        self._print_headers(result.headers)
        self._print_network(result)
        self._print_findings(result)

    def _print_score_breakdown(self, result: ScanResult) -> None:
        """Print the 100-point score allocation."""

        self._section("Score Breakdown")
        print(f"Certificate.............{result.score.certificate}/20")
        print(f"TLS.....................{result.score.tls}/20")
        print(f"Headers.................{result.score.headers}/20")
        print(f"Redirect................{result.score.redirect}/10")
        print(f"Cipher..................{result.score.cipher}/15")
        print(f"HSTS....................{result.score.hsts}/10")
        print(f"OCSP....................{result.score.ocsp}/5")
        print()

    def _print_certificate(self, result: ScanResult) -> None:
        """Print certificate metadata."""

        cert = result.certificate
        self._section("Certificate")
        print(f"Common Name:         {cert.common_name}")
        print(f"Organization:        {cert.organization}")
        print(f"Country:             {cert.country}")
        print(f"Issuer:              {cert.issuer}")
        print(f"Valid From:          {cert.valid_from}")
        print(f"Valid Until:         {cert.valid_until}")
        print(f"Days Remaining:      {cert.days_remaining}")
        print(f"Signature Algorithm: {cert.signature_algorithm}")
        print(f"Public Key Size:     {cert.public_key_size}")
        print(f"SAN Domains:         {', '.join(cert.san_domains[:8]) if cert.san_domains else 'None detected'}")
        print(f"Trusted:             {self._yes_no(cert.trusted)}")
        print(f"Hostname Valid:      {self._yes_no(cert.hostname_valid)}")
        print(f"Self-Signed:         {self._yes_no(cert.self_signed)}")
        print(f"OCSP Available:      {self._yes_no(bool(cert.ocsp_urls))}")
        print("Certificate Chain:")
        for item in cert.chain:
            print(f"  -> {item}")
        print()

    def _print_tls(self, result: ScanResult) -> None:
        """Print TLS versions and cipher details."""

        self._section("TLS and Cipher")
        for item in result.tls_versions:
            status = f"{ConsoleColors.GREEN}Supported{ConsoleColors.RESET}" if item.supported else f"{ConsoleColors.DIM}Not Supported{ConsoleColors.RESET}"
            risk = f"{ConsoleColors.RED}insecure{ConsoleColors.RESET}" if not item.secure else "secure"
            print(f"{item.name:8} {status} ({risk})")
        cipher = result.cipher
        print()
        print(f"Negotiated Cipher:   {cipher.name}")
        print(f"Protocol:            {cipher.protocol}")
        print(f"Encryption:          {cipher.encryption}")
        print(f"Key Exchange:        {cipher.key_exchange}")
        print(f"Forward Secrecy:     {self._yes_no(cipher.forward_secrecy)}")
        print(f"Cipher Strength:     {cipher.strength}")
        print(f"Weak Reasons:        {', '.join(cipher.weak_reasons) if cipher.weak_reasons else 'None detected'}")
        print()

    def _print_headers(self, headers: list[HeaderResult]) -> None:
        """Print HTTP security header status."""

        self._section("HTTP Security Headers")
        for header in headers:
            status = f"{ConsoleColors.GREEN}Present{ConsoleColors.RESET}" if header.present else f"{ConsoleColors.RED}Missing{ConsoleColors.RESET}"
            print(f"{header.name:38} {status}")
        print()

    def _print_network(self, result: ScanResult) -> None:
        """Print DNS, WHOIS, GeoIP, HSTS, redirect, mixed content, and ports."""

        self._section("Network and Web")
        print(f"IPv4:                {', '.join(result.dns.ipv4) if result.dns.ipv4 else 'None detected'}")
        print(f"IPv6:                {', '.join(result.dns.ipv6) if result.dns.ipv6 else 'None detected'}")
        print(f"Nameservers:         {', '.join(result.dns.nameservers) if result.dns.nameservers else 'Unknown'}")
        print(f"MX:                  {', '.join(result.dns.mx) if result.dns.mx else 'Unknown'}")
        print(f"CAA:                 {', '.join(result.dns.caa) if result.dns.caa else 'Unknown'}")
        print(f"DNSSEC:              {result.dns.dnssec}")
        print(f"Registrar:           {result.whois.registrar}")
        print(f"GeoIP:               {result.geoip.country}, {result.geoip.city} | {result.geoip.isp}")
        print(f"HSTS:                {self._yes_no(result.hsts.enabled)} max-age={result.hsts.max_age} includeSubDomains={result.hsts.include_subdomains} preload={result.hsts.preload}")
        print(f"HTTP -> HTTPS:       {self._yes_no(result.redirect.redirects_to_https)}")
        print(f"Redirect Chain:      {' -> '.join(result.redirect.chain) if result.redirect.chain else 'None'}")
        mixed_count = sum(
            len(items)
            for items in (
                result.mixed_content.http_images,
                result.mixed_content.http_css,
                result.mixed_content.http_javascript,
                result.mixed_content.http_fonts,
                result.mixed_content.http_ajax,
            )
        )
        print(f"Mixed Content Items: {mixed_count}")
        print("Ports:")
        for port in result.ports:
            print(f"  {port.port}: {port.status}")
        print()

    def _print_findings(self, result: ScanResult) -> None:
        """Print risk summary and recommendations."""

        self._section("Risk Summary")
        if result.findings:
            for finding in result.findings:
                print(f"{self._severity_color(finding.severity)}[{finding.severity}]{ConsoleColors.RESET} {finding.title}")
                print(f"  {finding.description}")
        else:
            print("No findings detected.")
        print()

        self._section("Recommendations")
        for recommendation in result.recommendations:
            print(f"- {recommendation}")
        if result.errors:
            print()
            self._section("Warnings / Skipped Checks")
            for error in result.errors[:12]:
                print(f"- {error}")
        print()

    def _run_with_spinner(self, label: str, work):
        """Run blocking work while a console spinner shows progress."""

        done = threading.Event()
        result_holder = {"value": None, "error": None}

        def worker() -> None:
            try:
                result_holder["value"] = work()
            except Exception as exc:
                result_holder["error"] = exc
            finally:
                done.set()

        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        frames = "|/-\\"
        index = 0
        while not done.is_set():
            print(f"\r{ConsoleColors.CYAN}{frames[index % len(frames)]}{ConsoleColors.RESET} {label}...", end="", flush=True)
            index += 1
            time.sleep(0.12)
        thread.join()
        print("\r" + " " * (len(label) + 8) + "\r", end="")
        if result_holder["error"]:
            raise result_holder["error"]
        return result_holder["value"]

    def _read_targets(self, path: Path) -> list[str]:
        """Read TXT/CSV targets, taking the first column for CSV rows."""

        targets: list[str] = []
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            value = line.split(",")[0].strip()
            if value and not value.startswith("#"):
                targets.append(value)
        return targets

    def _score_line(self, result: ScanResult) -> str:
        """Return a colored score line."""

        color = ConsoleColors.GREEN
        if result.score.total < 55:
            color = ConsoleColors.RED
        elif result.score.total < 75:
            color = ConsoleColors.YELLOW
        return f"{color}{result.domain}: {result.score.total}/100 {result.overall_rating}{ConsoleColors.RESET}"

    def _yes_no(self, value: bool) -> str:
        """Return a colored yes/no label."""

        return f"{ConsoleColors.GREEN}Yes{ConsoleColors.RESET}" if value else f"{ConsoleColors.RED}No{ConsoleColors.RESET}"

    def _severity_color(self, severity: str) -> str:
        """Return a color for a severity label."""

        return {
            "CRITICAL": ConsoleColors.RED + ConsoleColors.BOLD,
            "HIGH": ConsoleColors.RED,
            "MEDIUM": ConsoleColors.YELLOW,
            "LOW": ConsoleColors.CYAN,
        }.get(severity, ConsoleColors.RESET)

    def _section(self, title: str) -> None:
        """Print a section heading."""

        print(f"{ConsoleColors.BOLD}{ConsoleColors.BLUE}{title}{ConsoleColors.RESET}")
        print(f"{ConsoleColors.DIM}{'-' * len(title)}{ConsoleColors.RESET}")

    def _line(self, text: str, color: str = "") -> None:
        """Print one colored line."""

        print(f"{color}{text}{ConsoleColors.RESET}")

    def _prompt(self, label: str) -> str:
        """Return a styled input prompt."""

        return f"{ConsoleColors.CYAN}{label}>{ConsoleColors.RESET} "

    def _pause(self, message: str = "") -> None:
        """Wait for the user before returning to the menu."""

        if message:
            print()
            print(message)
        input(f"\n{ConsoleColors.DIM}Press Enter to continue...{ConsoleColors.RESET}")
