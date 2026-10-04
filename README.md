# HTTPS Security Checker

## Overview

HTTPS Security Checker is an interactive Python console application for reviewing website HTTPS, TLS, certificate, header, DNS, and network posture.

## Features

- TLS protocol and certificate inspection
- HTTP security-header analysis
- DNS and WHOIS information collection
- Redirect, connectivity, and endpoint checks
- Structured console summaries

## Requirements

Python 3.11+, internet access for remote checks, and the packages in `requirements.txt`.

## Installation

```bash
python -m venv .venv
python -m pip install -r requirements.txt
```

## Configuration

Set `HTTPS_CHECKER_SKIP_AUTO_INSTALL=1` to prevent automatic dependency installation when modules are missing.

## Running

```bash
python main.py
```

Enter the target through the interactive console.

## Security

Treat collected certificate, DNS, and network data as potentially sensitive. Use the checker only for defensive review and authorized assessment.

## Limitations

Results reflect the network path and server state at scan time. CDN behavior, rate limits, DNS caching, and blocked probes can affect findings.

## Disclaimer

Use only against systems you own or have permission to assess.
