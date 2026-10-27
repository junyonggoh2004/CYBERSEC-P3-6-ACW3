# CYBERSEC-P3-6-ACW3

Lab target for **CVE-2026-58415** — Apache HTTP Server WebDAV dead-property
disclosure (Medium, CVSS 5.3). Branch: `xamp-apache-webdav`.

To build the environment and reproduce the exploit, mitigation, and permanent-fix
tests, follow **[RUNBOOK.md](RUNBOOK.md)** top to bottom.

## Files

| File | Purpose |
|------|---------|
| [RUNBOOK.md](RUNBOOK.md) | Step-by-step reproduction guide (start here) |
| `verify.ps1` | Automated end-to-end check — builds both targets and asserts every expected result |
| `Dockerfile` | Vulnerable target — Apache httpd 2.4.68 + WebDAV |
| `Dockerfile69` | Patched target — httpd 2.4.69, for the permanent-fix test |
| `demo.txt` | Resource uploaded to the WebDAV collection |
| `proppatch.xml` | PROPPATCH body that plants the test marker property |
| `mitigation.conf` | Interim `LocationMatch` deny rule for `.DAV` |

## Automated verification

With Docker Desktop running, from the repository root:

```powershell
powershell -ExecutionPolicy Bypass -File verify.ps1
```

The script builds the 2.4.68 and 2.4.69 targets, runs the full exploit →
mitigation → permanent-fix flow, prints `PASS`/`FAIL` per step, tears everything
down, and exits non-zero if any check fails. It is the automated equivalent of
following [RUNBOOK.md](RUNBOOK.md) by hand.

## Scope and ethics

This is a contained, non-destructive lab for the INF2005 practicum. The target
binds only to `127.0.0.1` (loopback) on the tester's own machine — it is never
exposed to a bridged or public network. The demonstrated flaw is an
information-disclosure (read-only) issue affecting only the lab's own throwaway
container; there is no third-party target, no persistence, and no modification of
any resource. Use only in your own isolated environment.

## References

- CVE record — <https://www.cve.org/CVERecord?id=CVE-2026-58415>
- Apache HTTP Server 2.4 vulnerabilities (CVE-2026-58415) — <https://httpd.apache.org/security/vulnerabilities_24.html#CVE-2026-58415>
- NVD / OpenCVE entry — <https://app.opencve.io/cve/CVE-2026-58415>
- CWE-200: Exposure of Sensitive Information to an Unauthorized Actor — <https://cwe.mitre.org/data/definitions/200.html>
- Apache `mod_dav` / `mod_dav_fs` documentation — <https://httpd.apache.org/docs/2.4/mod/mod_dav.html>
