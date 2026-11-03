# CVE-2026-73636 — Apache mod_auth_digest Capture-Replay Bypass

Lab target for **CVE-2026-73636** — Apache HTTP Server `mod_auth_digest`
one-time-nonce **capture-replay authentication bypass** (High, CVSS 8.1,
CWE-294). Contributor: Kim, Jian Xuan. Branch: `xamp-apache-webdav`.

To build the environment and reproduce the exploit and permanent-fix test,
follow **[RUNBOOK.md](RUNBOOK.md)** top to bottom.

## What the flaw is

With Digest auth in one-time-nonce mode (`AuthDigestNonceLifetime 0`), each
server nonce is meant to be usable exactly once. The server's *only* record that
a nonce was already spent lives in a per-client entry in a fixed-size
shared-memory client list. On Apache ≤ 2.4.68, if that entry is evicted from the
list (the list is small, churned, or garbage-collected), the server loses the
record and **re-accepts a replayed `Authorization` header** (HTTP 200) — an
authentication bypass. Fixed in **2.4.69** (patch
[`fc722c6`](https://github.com/apache/httpd/commit/fc722c619fdf7f8eb69eb8bd4201265065cd3ac2)),
which tracks the nonce/nonce-count so a replayed one-time nonce is rejected
regardless of eviction.

## Threat model

**Simulated capture:** the exploit computes Alice's valid `Authorization` header
using her credentials, as a stand-in for an on-wire capture. This is a controlled
demonstration of the capture-replay bypass window, not a traffic-sniffing attack.
In a real capture-replay attack the header would instead be sniffed off the
network by a passive observer who never learns the password.

The security finding is in the **replay**: the captured header is re-sent verbatim
and, once the server has evicted the client entry, re-accepted (HTTP 200) even
though its one-time nonce was already spent. The eviction is driven by the churn
step, which performs repeated legitimate logins as Alice — each a fresh handshake
computed from her credentials — to push the captured nonce's entry out of the
fixed-size shared-memory client list.

## Files

| File | Purpose |
|------|---------|
| [RUNBOOK.md](RUNBOOK.md) | Step-by-step reproduction guide (start here) |
| `verify.ps1` | Automated end-to-end check — builds both targets, asserts bypass-then-blocked, tears down |
| `Dockerfile` | Vulnerable target — Apache httpd 2.4.68 + Digest auth |
| `Dockerfile69` | Patched target — httpd 2.4.69, for the permanent-fix test |
| `exploit.py` | Capture-replay PoC (Python standard library only; targets either port) |

## Automated verification

With Docker Desktop running, from the repository root:

```powershell
powershell -ExecutionPolicy Bypass -File digest-auth/verify.ps1
```

The script builds the 2.4.68 and 2.4.69 targets, runs the capture-replay exploit
against each, prints `PASS`/`FAIL` per step, tears everything down, and exits
non-zero if any check fails. It is the automated equivalent of following
[RUNBOOK.md](RUNBOOK.md) by hand. Last run: 16/16 passed (2026-11-02).

## Scope and ethics

This is a contained, non-destructive lab for the INF2005 practicum. Both targets
bind only to `127.0.0.1` (loopback) on the tester's own machine — never exposed
to a bridged or public network. The exploit replays a header the script computes
for the lab's own throwaway test user against the lab's own container; there is no
third-party target, no persistence, and no modification of any resource. Use only
in your own isolated environment.

## Verification status (confirmed vs. inferred)

- **Confirmed (live, 2026-11-01):** 2.4.68 is bypassed, 2.4.69 blocks the same
  replay — observed against freshly built containers. The before/after boundary
  is established behaviourally.
- **Confirmed (source):** patch `fc722c6` exists and reworks `mod_auth_digest`
  nonce/nonce-count handling (a large 2.4.x backport merge, not a single-purpose
  fix).
- **Could not verify:** the cve.org record for CVE-2026-73636 returned an empty
  page (no description/CVSS/affected list) at the time of testing. The CVSS 8.1 /
  High and CWE-294 classification come from the course CVE sheet and the patch,
  not the CVE record. Confirm the official wording against the Apache
  `vulnerabilities_24.html` advisory before citing it.

## References

- CVE record — <https://www.cve.org/CVERecord?id=CVE-2026-73636>
- Patch commit `fc722c6` — <https://github.com/apache/httpd/commit/fc722c619fdf7f8eb69eb8bd4201265065cd3ac2>
- Apache HTTP Server 2.4 vulnerabilities — <https://httpd.apache.org/security/vulnerabilities_24.html>
- CWE-294: Authentication Bypass by Capture-replay — <https://cwe.mitre.org/data/definitions/294.html>
- Apache `mod_auth_digest` documentation — <https://httpd.apache.org/docs/2.4/mod/mod_auth_digest.html>
