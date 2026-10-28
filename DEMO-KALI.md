# Demo Runbook — Reproducing CVE-2026-18503 on a Kali Linux VM

A step-by-step script for running and **demonstrating** the CVE-2026-18503
(`csv.Sniffer` Denial of Service) exploit and its remediation inside a Kali Linux
VM. Follow it from top to bottom.

The lab is pure **Python 3 standard library** — Kali already has Python 3, so
there is nothing to install.

---

## Part 0 — Get the lab into Kali VM 

You only need to do this once. Pick whichever transfer matches your setup.

### Option A — shared folder or USB

Copy the complete `cve-2026-18503-lab` folder into the VM using the VMware or
VirtualBox shared folder, or a USB drive. Then copy it into your home directory in
Kali if necessary.

### Option B — `scp` from the host Mac (connect local SSH to Kali VM)

```bash
# in Kali:
sudo systemctl enable --now ssh
ip -4 addr                  # note Kali's IP

# in a Mac terminal:
scp -r "<path-to>/cve-2026-18503-lab" <kali-user>@<kali-ip>:/home/<kali-user>/

#replace kali-user with your kali userame, and kali-ip with the ip address shown in ip -4
```

### Option C — clone the repository

If the lab has been pushed to a repository that Kali can access:

```bash
cd ~
git clone <repository-url>
```

### Then, enter the folder

```bash
cd ~
cd cve-2026-18503-lab
ls          # expect: app  docker  exploit  remediation  report  scripts  tests
```

> If a command says "No such file", you are not inside the lab folder. Run `pwd`
> (should end in `/cve-2026-18503-lab`) and `find ~ -name run_local.sh 2>/dev/null`
> to locate it. Never use `/Users/...` paths in Kali — those exist locally.

This runbook uses one Kali VM with two terminals: Terminal 1 is the local target
service and Terminal 2 runs the penetration test. These commands bind the server
to `127.0.0.1`, so this is not a cross-VM attacker-to-target setup.

---

## Part 1 — One-time setup check

```bash
chmod +x scripts/*.sh
scripts/setup_kali.sh
```

**Expected:** `[ok] python3 present: Python 3.x` followed by a printed list of run
steps. If Python 3 were missing it would tell you the `apt install` command (it
won't be — Kali ships it).

---

## Part 2 — DEMO A: reproduce the Denial of Service (two terminals)

This is the money shot: one small request freezes the whole service.

**Terminal 1 — start the VULNERABLE server:**
```bash
cd ~/cve-2026-18503-lab
scripts/run_target.sh vuln 127.0.0.1 8000
```
Expected:
```
[server] mode=vuln :: VULNERABLE (pre-patch Sniffer) -- expect DoS on crafted input
[server] listening on http://127.0.0.1:8000  (single-threaded)
```

**Terminal 2 — launch the exploit:**
```bash
cd ~/cve-2026-18503-lab
python3 exploit/exploit.py --host 127.0.0.1 --port 8000 --n 6000
```

While it runs, the malicious request occupies Terminal 1's single request worker
for several seconds. For extra effect, open a browser in Kali to
`http://127.0.0.1:8000/health` during the freeze — it hangs until the attack
finishes.

**Expected end of Terminal 2:**
```
[exploit] benign  /sniff response: {... "elapsed_ms": 1.0}
[exploit] sending malicious /sniff: shape=comma_quote_gap n=6000 bytes=132000 ...
[exploit] malicious /sniff returned in several seconds ...
[exploit] concurrent /health probes while attacking: 3 ok, 5 stalled/timed-out ...
[VERDICT] DENIAL OF SERVICE REPRODUCED ...
exit code 2
```

Stop the server with **Ctrl+C** in Terminal 1 when done.

**Turn the dial (optional):** bigger `--n` = longer hang. Timing depends on the
machine, so benchmark before the assessment and choose a value that keeps the
demonstration short. Only the exploit's `--n` value matters.

---

## Part 3 — DEMO B: prove the remediation (same attack, now harmless)

**Terminal 1 — restart in FIXED mode:**
```bash
scripts/run_target.sh fixed 127.0.0.1 8000
```
Expected banner: `[server] mode=fixed :: FIXED (remediated Sniffer: linear regex + input cap)`

**Terminal 2 — run the identical exploit:**
```bash
python3 exploit/exploit.py --host 127.0.0.1 --port 8000 --n 6000
```
**Expected:**
```
[exploit] malicious /sniff returned in ~0.005s ...
[exploit] concurrent /health probes while attacking: 3 ok, 0 stalled/timed-out ...
[VERDICT] Service stayed responsive ...
exit code 0
```

---

## Part 4 — DEMO C: the evidence slides

Single-terminal, no server needed.

**Super-linear vs linear growth:**
```bash
python3 exploit/benchmark.py
```

**Automated proof:**
```bash
python3 tests/test_remediation.py
python3 tests/test_exploit_verdict.py
```
Expected: `ALL TESTS PASSED` — asserts the fix is fast and correct, and that the
vulnerable version really is much slower. The verdict test also checks that a
client timeout alone is not presented as a confirmed service outage.

---

## Part 5 — (Optional) real vulnerable CPython via Docker

Proves it against the genuine standard library, not the lab's vendored copy.
Needs Docker (`sudo apt install -y docker.io docker-compose-v2` on Kali).

```bash
docker compose -f docker/docker-compose.yml up --build
# in another terminal:
python3 exploit/exploit.py --port 8000   # python:3.12.0  -> DoS reproduced
python3 exploit/exploit.py --port 8001   # python:3.12.14 -> harmless (patched)
```

---

## Suggested 3-minute demo order

1. **Setup** (Part 1) — "Kali, Python 3, no installs."
2. **Attack** (Part 2) — start vuln server, run exploit, show the freeze + verdict.
3. **Fix** (Part 3) — restart fixed server, rerun exploit, show it shrug it off.
4. **Evidence** (Part 4) — benchmark table + passing tests.
5. **Wrap** — point to `cve-2026-18503-lab/report/REPORT.md` for identification → exploitation →
   remediation with measured numbers.

---

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `No such file or directory` on `scripts/...` | Not inside the lab folder. `cd ~/cve-2026-18503-lab` (confirm with `pwd`). |
| Cannot copy the folder into Kali | Use a shared folder, USB drive, `scp -r`, or `git clone`; paths beginning with `/Users/...` exist only on the Mac. |
| `Permission denied` running a script | `chmod +x scripts/*.sh`. |
| Exploit says "cannot reach ... is the server running?" | Start the server (Part 2/3) first, in a separate terminal, on the same `--port`. |
| Attack returns fast even in `vuln` mode | Increase `--n` (e.g. `--n 12000`); a very fast CPU needs a bigger payload to show seconds. |
| `python3: command not found` | `sudo apt update && sudo apt install -y python3`. |
