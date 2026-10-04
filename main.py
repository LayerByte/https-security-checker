from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path


REQUIRED_MODULES = (
    "requests",
    "certifi",
    "cryptography",
    "dns",
    "whois",
)


def auto_install_requirements() -> None:
    """Install requirements.txt automatically when modules are missing."""

    if getattr(sys, "frozen", False) or os.environ.get("HTTPS_CHECKER_SKIP_AUTO_INSTALL") == "1":
        return

    missing = [module for module in REQUIRED_MODULES if importlib.util.find_spec(module) is None]
    if not missing:
        return

    requirements_path = Path(__file__).with_name("requirements.txt")
    if not requirements_path.exists():
        raise RuntimeError(f"Missing requirements file: {requirements_path}")

    print("Missing Python packages detected:")
    for module in missing:
        print(f"  - {module}")
    print("\nInstalling requirements automatically. This may take a few minutes...\n")

    subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", "pip"])
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", str(requirements_path)])


def main() -> None:
    """Start the Windows console application."""

    auto_install_requirements()

    from app.console import HTTPSCheckerConsole

    app = HTTPSCheckerConsole()
    app.run()


if __name__ == "__main__":
    main()
