# Corrections to the CVE-2026-58415 runbook

Apply these to your existing `cve-2026-58415-runbook.md`. The CVE facts
(affected 2.4.0-2.4.68, fixed 2.4.69, CVSS 5.3 Medium, unauthenticated read
of WebDAV dead properties) were all verified correct against Red Hat / SUSE /
Debian / OpenCVE. Only the on-disk filename handling needs fixing.

## 1. The state filename is NOT `properties`

mod_dav_fs keeps one SDBM database **per resource, named after the resource**,
inside the `.DAV` state directory — confirmed in the mod_dav_fs source
(`modules/dav/fs/dbm.c`): "The filename of the database is equivalent to the
target filename."

So the property database for a resource called `demo.txt` is `.DAV/demo.txt`,
and because the official httpd image builds APR with SDBM, that is normally a
**pair** of files:

- `.DAV/demo.txt.pag`  <- the data (this is what carries the stored property value)
- `.DAV/demo.txt.dir`  <- the index

The exact extensions depend on the APR DBM backend compiled into the image, so
never hard-code the name. Discover it from the directory listing.

**Action:** everywhere the runbook says the file is `properties`, change the
example to `demo.txt.pag` and add a note that the real name comes from the
listing.

## 2. Make the directory listing the primary discovery step

The stock httpd image has `Options Indexes` enabled on `htdocs`, and the
`<Directory webdav>` block does not override it, so a request to the `.DAV/`
directory returns an autoindex listing that shows the real filename. Use that
listing to read the actual filename first, then fetch that exact file. This
removes the guesswork that the old "may return a listing" wording left open.

Recommended order for the exploit section:
1. On the target: `docker exec dav ls -la htdocs/webdav/.DAV/`  (note the real name)
2. From the attacker: request the `.DAV/` directory and read the filename from the listing
3. Fetch that exact file over HTTP
4. Run `strings` + `grep` on the downloaded `.pag` file to surface the stored value

## 3. Fix the OPTIONS probe

`curl -I -X OPTIONS ...` mixes HEAD-only output with an OPTIONS method.
Use `curl -i -X OPTIONS ...` instead — still shows the `DAV:` and `Allow`
headers, without the method/flag mismatch.

## 4. Mitigation and teardown: unchanged

The `<LocationMatch "(^|/)\.DAV"> Require all denied </LocationMatch>` rule,
the `httpd -t` syntax check, the graceful reload, and the teardown steps are
all correct as written. The note that PROPFIND still works after the mitigation
is a good, accurate touch — it shows the fix is surgical.

## Project reminders (from the ACW3 spec)

- This is one 5.3 vuln. You need 3 approved vulnerabilities demoed and a total
  CVSS of at least 20 points across the report, so plan ~3-4 more.
- Demo reward caps at 95% when the highest severity is Medium; one High/Critical
  in the set lifts that ceiling to 100%. httpd 2.4.69 also fixed several 9.8s on
  the same server, which could reuse this exact target environment.
