# Corrections to the CVE-2026-58415 runbook

All items below were **verified by actually building and running the target**
(httpd 2.4.68 in Docker) on 2026-10-22, not just reasoned about. The CVE facts
(affected 2.4.0-2.4.68, fixed 2.4.69, CVSS 5.3 Medium, unauthenticated read of
WebDAV dead properties) were confirmed correct against Red Hat / SUSE / Debian /
OpenCVE. Two things in the original Dockerfile/runbook were wrong and would have
broken the live demo; both are now fixed in the `Dockerfile` in this repo.

## CRITICAL FIX 1 - ownership must be www-data, not daemon

The original Dockerfile did `chown -R daemon:daemon var htdocs/webdav`. On this
httpd image the worker processes run as **www-data** (confirmed: the httpd.conf
shipped in the image has `User www-data` / `Group www-data`). With the dirs
owned by `daemon`, the very first PUT fails:

```
PUT /webdav/demo.txt  ->  HTTP 500
[dav:error] Could not open the lock database.  [500, #400]
```

Fix (already applied in this repo's Dockerfile): chown to `www-data:www-data`.
After the fix, a clean rebuild gives PUT 201 / PROPPATCH 207 with no manual
intervention. Older httpd images used `daemon`, which is why the stale value was
there.

## FIX 2 - the state filename is `demo.txt`, not `properties` (and not a .pag/.dir pair)

Verified by `ls` inside the container after seeding a property:

```
htdocs/webdav/.DAV/
-rwxr-xr-x 1 www-data www-data 12288 ... demo.txt
```

- It is a **single file** named exactly after the resource (`demo.txt`).
- It is NOT named `properties` (the original runbook's assumption).
- It is NOT a `.pag` / `.dir` SDBM pair (an earlier guess of mine that the live
  test disproved - this APR build writes one file).

So for the demo: seed a property on `demo.txt`, then the state file to read is
`/webdav/.DAV/demo.txt`. If you name your resource something else, the state
file takes that name - always read the real name from the listing rather than
hard-coding it.

The `.DAV/` directory itself is also browsable (the stock image has
`Options Indexes` on for htdocs and the webdav block doesn't override it), so
listing `/webdav/.DAV/` shows the filename over HTTP too. Make that listing your
discovery step.

## FIX 3 - OPTIONS probe flag

`curl -I -X OPTIONS ...` mixes HEAD-only output with an OPTIONS method. Use
`curl -i -X OPTIONS ...` instead. (Verified: returns `DAV: 1,2` and the full
`Allow:` list including PROPFIND/PROPPATCH/LOCK.)

## Verified exploit + mitigation results (2026-10-22)

| Step | Result |
|------|--------|
| `httpd -v` | Apache/2.4.68 (Unix) |
| base `GET /` | HTTP 200 |
| `OPTIONS /webdav/` | 200, `DAV: 1,2` present |
| `PUT /webdav/demo.txt` | 201 |
| `PROPPATCH` marker property | 207 |
| state file on disk | `.DAV/demo.txt` (single file, 12288 bytes) |
| unauth `GET /webdav/.DAV/demo.txt` | 200, marker string present -> disclosure confirmed |
| after `LocationMatch` deny + graceful reload | 403 |
| `PROPFIND /webdav/demo.txt` after mitigation | 207 (legit WebDAV still works - fix is surgical) |

Mitigation that was verified to work (copied into the container as
`conf/mitigation.conf` and Include'd, to avoid shell-quoting mangling of the
regex):

```
<LocationMatch "(^|/)\.DAV">
    Require all denied
</LocationMatch>
```

Note: appending this block via `docker exec ... sh -c 'printf ...'` mangles the
regex (the `<` is read as a shell redirect). On the demo, either edit the conf
inside the container with an editor, or copy a prepared `.conf` file in and
`Include` it.

## Project reminders (from the ACW3 spec)

- This is one 5.3 vuln. You need 3 approved vulnerabilities demoed and a total
  CVSS of at least 20 points across the report, so plan ~3-4 more.
- Demo reward caps at 95% when the highest severity is Medium; one High/Critical
  in the set lifts that ceiling to 100%. httpd 2.4.69 also fixed several 9.8s on
  the same server, which could reuse this exact target environment.
