"""Utility functions for input normalization, logging, and formatting."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import urlparse


PROJECT_ROOT = Path(sys.executable).resolve().parent if getattr(sys, "frozen", False) else Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT_ROOT / "data"


def normalize_target(raw_value: str) -> tuple[str, str, str]:
    """Validate and normalize user input into HTTPS URL, domain, and original URL."""

    value = raw_value.strip()
    if not value:
        raise ValueError("Please enter a website or domain.")

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value):
        value = f"https://{value}"

    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Only HTTP and HTTPS websites are supported.")

    domain = parsed.hostname or ""
    if not domain or not re.match(r"^[a-zA-Z0-9.-]+$", domain):
        raise ValueError("The website domain is not valid.")

    normalized = f"https://{domain}"
    if parsed.port:
        normalized += f":{parsed.port}"
    if parsed.path and parsed.path != "/":
        normalized += parsed.path

    return normalized, domain, value


def flatten_date(value: object) -> str:
    """Convert WHOIS/date-library values into a readable string."""

    if isinstance(value, list):
        value = next((item for item in value if item), None)
    return str(value) if value else "Unknown"


def limit_list(items: list[str], max_items: int = 30) -> list[str]:
    """Keep UI and reports readable when a page contains many matching assets."""

    return items[:max_items]
