# CYBERSEC-P3-6-ACW3

Lab target for **CVE-2026-58415** — Apache HTTP Server WebDAV dead-property
disclosure (Medium, CVSS 5.3). Branch: `xamp-apache-webdav`.

To build the environment and reproduce the exploit, mitigation, and permanent-fix
tests, follow **[RUNBOOK.md](RUNBOOK.md)** top to bottom.

## Files

| File | Purpose |
|------|---------|
| [RUNBOOK.md](RUNBOOK.md) | Step-by-step reproduction guide (start here) |
| `Dockerfile` | Vulnerable target — Apache httpd 2.4.68 + WebDAV |
| `Dockerfile69` | Patched target — httpd 2.4.69, for the permanent-fix test |
| `demo.txt` | Resource uploaded to the WebDAV collection |
| `proppatch.xml` | PROPPATCH body that plants the test marker property |
| `mitigation.conf` | Interim `LocationMatch` deny rule for `.DAV` |
