# CVE-2026-73636 — Apache mod_auth_digest Capture-Replay Bypass: Reproduction Runbook

**Report section this covers:** Section 5 (CVE-2026-73636) and Appendices A.3, B.3,
C.3, D.3 of the INF2005 P3-6 ACW3 report.

**What this demonstrates:** on Apache httpd ≤ 2.4.68 with Digest authentication in
one-time-nonce mode (`AuthDigestNonceLifetime 0`), a captured `Authorization`
header can be **replayed and re-accepted** once the server has evicted the
client's entry from its fixed-size shared-memory client list. The server's only
record that a one-time nonce was already spent lives in that entry; lose the
entry, and the replay succeeds (HTTP 200) — an authentication bypass. Fixed in
**2.4.69** (patch
[`fc722c6`](https://github.com/apache/httpd/commit/fc722c619fdf7f8eb69eb8bd4201265065cd3ac2)),
which tracks the nonce/nonce-count so a replayed one-time nonce is rejected
regardless of eviction.

This runbook is written to be followed top to bottom by a human tester. Each step
states **what you run**, **what you should see**, and the **report figure/command
ID** it produces.

> ### Confirmed vs. inferred — read first
> - **Confirmed (live testing, 2026-11-01):** the replay behaviour in every step
>   below was observed directly against freshly built 2.4.68 and 2.4.69 containers.
>   The before/after boundary (2.4.68 vulnerable, 2.4.69 fixed) is established
>   **behaviourally**, not assumed.
> - **Confirmed (source):** patch `fc722c6` exists on the Apache `httpd` 2.4.x
>   branch and reworks `mod_auth_digest` nonce / nonce-count handling. It is a
>   large backport **merge** (it also drops RFC 2069/qop support and fixes
>   expression-based `AuthName`), so it is not a single-purpose fix labelled for
>   this one issue.
> - **Could NOT verify:** the authoritative CVE record at cve.org for
>   CVE-2026-73636 returned an **empty/unpopulated page** — no description, CVSS,
>   or affected-version list. The "capture-replay" framing and the CVE-to-version
>   mapping therefore come from the patch and from live behaviour, **not** from the
>   CVE record. If the report must cite the official text, pull it from the Apache
>   `vulnerabilities_24.html` advisory instead.

---

## 0. Prerequisites

| Requirement | Version used in the assessment |
|-------------|--------------------------------|
| Docker Desktop (WSL2 backend), Windows 11 host | Docker engine 29.9.2 |
| Python on the host | 3.13 (standard library only — no `pip`, no internet) |
| `curl` on the host | 8.x (ships with Windows 10/11) |
| This repository branch | `xamp-apache-webdav` |

Run every command from the repository root (the folder containing the
`digest-auth/` directory). The exploit is issued from the **Windows host** against
the loopback-bound container. The ports are mnemonic: **8068** = the 2.4.68
target, **8069** = the 2.4.69 target.

Files used (all in `digest-auth/`):

- `Dockerfile` — builds the vulnerable target (httpd 2.4.68).
- `Dockerfile69` — builds the patched target (httpd 2.4.69) for the fix test.
- `exploit.py` — the capture-replay PoC (stdlib only; targetable at either port).

### Running in a Linux VM

The commands below are written for Windows PowerShell. The Dockerfiles, `exploit.py`,
and all results are identical on a Linux VM — only three command names differ:

| PowerShell (as written) | Linux shell |
|-------------------------|-------------|
| `curl.exe ...` | `curl ...` |
| `httpd -M \| findstr auth_digest` | `httpd -M \| grep auth_digest` |
| `python digest-auth/exploit.py ...` | `python3 digest-auth/exploit.py ...` |

The `docker ...` commands (including the in-container `grep -B2 -A8`) are the same on
both. `verify.ps1` needs PowerShell — on Linux install `pwsh`, or just follow the
steps below by hand.

**Two-VM (separate attacker/victim) variant:** run the target container on the victim
VM with `-p 8068:80` (drop the `127.0.0.1:` so it listens on the VM's interface,
allow inbound 8068 on its firewall), then run the exploit from the attacker VM with
`python3 digest-auth/exploit.py --host <victim-ip> --port 8068`. All status codes and
verdicts are unchanged; only the target address differs.

---

## 1. Build and run the vulnerable target  *(report Appendix A.3)*

```powershell
docker build -t digest-vuln:2.4.68 -f digest-auth/Dockerfile digest-auth
docker run -d --rm --name digest-vuln -p 127.0.0.1:8068:80 digest-vuln:2.4.68
```

**Expect:** the build completes and `docker run` prints a container ID. The target
is reachable at `http://127.0.0.1:8068/` — **loopback only**, never on a bridged or
public interface.

> The `.htdigest` credential (`alice` / `password123`, realm `secret`) is generated
> at build time with `md5sum`, not the interactive `htdigest` binary, so the build
> is deterministic and offline.

---

## 2. Confirm the target version and module  *(command B3.1 → Figure B3.1)*

```powershell
docker exec digest-vuln httpd -v
docker exec digest-vuln httpd -M 2>&1 | findstr auth_digest
```

**Expect:**
- `httpd -v` → `Server version: Apache/2.4.68 (Unix)`.
- `httpd -M` → lists `auth_digest_module` (**shared**/enabled).

*Capture as Figure B3.1.*

---

## 3. Confirm the vulnerable configuration  *(command B3.2 → Figure B3.2)*

```powershell
docker exec digest-vuln sh -c "grep -B2 -A8 'htdocs/secret' conf/httpd.conf"
```

> Use `-B2 -A8` (not just `-A8`). `AuthDigestShmemSize 1024` sits two lines *above*
> the `<Directory>` line, so a plain `grep -A8 'htdocs/secret'` starts at the
> directory block and hides it. `-B2` includes the two preceding lines so both
> settings show in one screenshot.

**Expect:** two lines above the block — `ServerName localhost` and
**`AuthDigestShmemSize 1024`** — then the `/secret` directory block showing
`AuthType Digest`, `AuthName "secret"`, `AuthDigestProvider file`, and the key line
**`AuthDigestNonceLifetime 0`** (one-time-nonce mode — the vulnerable setting).

> `AuthDigestShmemSize 1024` is a **demo aid, not part of the vulnerability.** The
> spent-nonce record lives in this shared-memory client list; a small segment makes
> the entry eviction that opens the replay window happen in ~60 requests instead of
> thousands, so the live demo is fast and deterministic. The flaw exists at any
> shmem size — a larger one just needs proportionally more traffic to evict the
> entry.

*Capture as Figure B3.2.*

---

## 4. Confirm Digest auth is enforced  *(command B3.3 → Figure B3.3)*

```powershell
curl.exe -i http://127.0.0.1:8068/secret/
curl.exe -i --digest -u alice:password123 http://127.0.0.1:8068/secret/
```

**Expect:**
- Unauthenticated GET → `HTTP/1.1 401 Unauthorized` with a
  `WWW-Authenticate: Digest realm="secret", nonce="...", algorithm=MD5,
  opaque="...", qop="auth"` header.
- With correct Digest credentials → `HTTP/1.1 200 OK`, the `FLAG{...}` body, and
  an `Authentication-Info:` response header containing a **`nextnonce=`** — the
  one-time-nonce bookkeeping the exploit has to defeat.

*Capture as Figure B3.3.*

---

## 5. Capture, replay, and bypass  *(command B3.4 → Figure B3.4)*

```powershell
python digest-auth/exploit.py --host 127.0.0.1 --port 8068
```

The script (standard library only) does the full attack:

1. **Simulated capture** — the exploit computes Alice's valid `Authorization`
   header using her credentials, as a stand-in for an on-wire capture. This is a
   controlled demonstration of the capture-replay bypass window, **not** a
   traffic-sniffing attack: the header is computed, not sniffed. It completes one
   valid handshake as `alice` and prints the exact header it sent.
2. **Immediate replay** — replays that header at once. **Expect 401** (`stale`):
   while the client entry survives, the one-time nonce is correctly refused. This
   proves the protection is normally working.
3. **Evict + replay** — issues `--churn` (default 60) further legitimate logins as
   `alice` (each a fresh handshake computed from her credentials) to push the
   captured nonce's entry out of the shared-memory client list, then replays the
   **same** captured header. **Expect 200 — the bypass.**

**Expect (the whole point):** the run ends with

```
    -> replay after eviction: 200 accepted - BYPASS
RESULT: VULNERABLE (BYPASS) - a replayed one-time-nonce header was
        ACCEPTED after client-entry eviction (HTTP 200).
```

and exits `0`. *Capture the full output as Figure B3.4. This is the disclosure —
a spent credential re-accepted without re-authentication.*

> **Mechanism (confirmed by the step-2/step-3 behaviour above, matching patch
> `fc722c6`):** the server records a spent one-time nonce only in the per-client
> entry in the shared-memory client list. Immediate replay is caught because the
> entry still holds the record (step 2 → 401). Once the entry is evicted (step 3),
> the server has no memory the nonce was used and re-accepts it (→ 200). The 2.4.69
> patch tracks the nonce/nonce-count so eviction no longer reopens the window.

---

## 6. Verify the permanent fix — upgrade to 2.4.69  *(report Appendix D.3)*

Build and run the patched target **separately**, on port 8069, with the **identical**
configuration (no workaround applied):

```powershell
docker build -t digest-fixed:2.4.69 -f digest-auth/Dockerfile69 digest-auth
docker run -d --rm --name digest-fixed -p 127.0.0.1:8069:80 digest-fixed:2.4.69
```

Run the **same** exploit against port 8069:

```powershell
docker exec digest-fixed httpd -v
python digest-auth/exploit.py --host 127.0.0.1 --port 8069
```

**Expect:**
- `httpd -v` → `Apache/2.4.69` *(evidence D1)*.
- Step 1 of the PoC still authenticates (200) — Digest auth itself works *(D2)*.
- Immediate replay → 401 **and** replay-after-eviction → **401** *(evidence D3)*.
- The run ends with `RESULT: NOT VULNERABLE - replay rejected in every condition`
  and exits `2`.

Because the only change from Section 5 is the base image (`2.4.68` → `2.4.69`),
the different outcome is attributable to the upgrade alone. *This is the before/after
in Appendix D.3.*

---

## 7. Reset / teardown  *(report Appendix A.3)*

```powershell
docker rm -f digest-vuln digest-fixed
docker rmi digest-vuln:2.4.68 digest-fixed:2.4.69
# The httpd:2.4.68 / httpd:2.4.69 base images are shared with the 58415 lab — keep them.
```

(The containers were started with `--rm`, so they also clean themselves up on stop.)

---

## Expected-results summary (quick reference)

| Step | Command ID | Action | Expected result |
|------|-----------|--------|-----------------|
| 2 | B3.1 | `httpd -v` / `-M` | Apache/2.4.68; `auth_digest_module` loaded |
| 3 | B3.2 | `grep -B2 -A8` config | `AuthDigestShmemSize 1024` + `AuthDigestNonceLifetime 0`, Digest auth on `/secret` |
| 4 | B3.3 | unauth GET / digest GET | 401 + `WWW-Authenticate: Digest`; then 200 + `nextnonce` |
| 5 | B3.4 | `exploit.py --port 8068` | immediate replay 401; **replay after eviction 200 — BYPASS** |
| 6 | D1–D3 | `exploit.py --port 8069` | auth 200; **both replays 401 — fixed at source** |

All steps above were verified end to end against live Docker builds on
**2026-11-01**; every expected result matched.

---

## Notes from live testing (2026-11-01)

Corrections and observations made while building and running the target, kept here
so the steps above are known-good rather than assumed.

1. **The replay is NOT accepted immediately.** A naive "capture then replay at once"
   test returns 401, because the spent-nonce record still exists in the client
   entry. The bypass requires that entry to be **evicted** first (step 5.3). An
   earlier assumption that natural time-based cleanup under `NonceLifetime 0` would
   suffice was dropped in favour of client-list churn, which is fast and
   deterministic for a live demo.

2. **The one-time nonce carries a counter and the server issues a `nextnonce`.**
   Observed in the challenge nonces (`AAAAAAAAAAA=…`, `AQAAAAAAAAA=…`) and in the
   `Authentication-Info: … nextnonce=…` header on each 200. This is the
   one-time-nonce bookkeeping; the exploit works by making the server forget the
   captured nonce's entry, not by forging a valid `nextnonce`.

3. **`AuthDigestShmemSize 1024` is a demo aid, not the vulnerability.** It only
   sets how much traffic is needed to evict the entry. The flaw is the reliance on
   evictable shared-memory state as the sole replay-protection record.

4. **The CVE record is unpopulated.** cve.org returned no description/CVSS/affected
   list for CVE-2026-73636 at the time of testing. All vulnerability facts in this
   runbook are grounded in patch `fc722c6` and in observed behaviour, not in the
   CVE record. Confirm the official wording against the Apache advisory before
   citing it in the report body.

5. **Standard-library exploit, offline.** `exploit.py` uses only `http.client` and
   `hashlib` — no `requests`, no `pip`, no outbound internet. The container needs
   no network access beyond the loopback publish.
