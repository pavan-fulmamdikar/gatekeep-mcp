# Security Policy

## Supported Versions

Security fixes are applied to the latest `0.2.x` release on `main`.

## Reporting a Vulnerability

If you discover a security bypass (e.g., DLP evasion, SSRF / DNS-rebinding bypass, SQL/shell parser evasion, provenance taint escape, RBAC/SoD bypass, or Saga WAL corruption):

1. **Please do NOT open a public GitHub Issue** with a live exploit payload before coordinated disclosure.
2. Use GitHub's **Private Vulnerability Reporting** ("Security" tab -> "Report a vulnerability") on this repository, or open a minimal contact issue requesting a private channel.
3. Include a minimal reproduction script (or JSON-RPC payload), expected verdict vs. observed verdict, and Gatekeep version.

We aim to acknowledge reports within 48 hours and publish a regression test alongside every fix.
