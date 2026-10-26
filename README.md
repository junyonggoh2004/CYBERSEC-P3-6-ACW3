# ACW 3 Vulnerability Identification:

## CVE-2026-18503: csv.Sniffer Denial of Service

A self-contained lab that **identifies**, **exploits**, and **remediates**
[CVE-2026-18503](https://www.cve.org/CVERecord?id=CVE-2026-18503): a super-linear
CPU (ReDoS-style) **Denial of Service** in CPython's `csv.Sniffer.sniff()`.

Everything here runs on the **Python 3 standard library only** — no `pip install`,
no network — so it behaves identically on **macOS** and in a **Kali Linux VM**.
Docker is optional and only used to demonstrate the flaw against a real pinned
vulnerable CPython.

> ⚠️ **Scope / ethics.** This is a contained, non-destructive
> algorithmic-complexity DoS that only burns CPU inside the lab's own process on
> `127.0.0.1`. There is no network flooding, no persistence, no third-party
> target. Use it only in your own isolated environment for the practicum.

## The vulnerability in one paragraph

`csv.Sniffer._guess_quote_and_delimiter()` locates quoted fields using four
regexes that match the field body with a **lazy `.*?`** quantifier. Fed
attacker-controlled input via `re.findall`, a long run of quote-like characters
makes the engine re-scan the remainder of the input from many start positions, so
work grows **quadratically** with input size (CWE-1176). Upstream fixed it by
replacing `.*?` with a non-backtracking group
`(?:(?P=quote){2}|(?!(?P=quote)).)*+`.

## Layout

```
cve-2026-18503-lab/  application, exploit, scripts, tests, Docker files, and report
DEMO-KALI.md          individual Kali VM demonstration runbook
DEMO-TWO-VM.md        consolidated host-only two-VM demonstration runbook
```

## Run it locally (macOS / Linux)

From the repository root:

```bash
cd cve-2026-18503-lab

# 1. Reproduce the Denial of Service (vulnerable server)
scripts/run_local.sh vuln 8000 3000
#    -> malicious request takes seconds on typical hardware; /health probes time out
#       [VERDICT] DENIAL OF SERVICE REPRODUCED   (exit code 2)

# 2. Confirm the remediation (fixed server)
scripts/run_local.sh fixed 8000 3000
#    -> same attack returns in ~3 ms; health checks never stall
#       [VERDICT] Service stayed responsive       (exit code 0)

# 3. Offline before/after evidence (no server)
python3 exploit/benchmark.py

# 4. Tests
python3 tests/test_remediation.py      # or: pytest tests/
python3 tests/test_exploit_verdict.py # DoS verdict requires health-stall evidence
bash tests/test_runtime.sh             # server config + runner exit codes
```

Run it manually to demo live exploit:

```bash
# terminal A: start the vulnerable target
cd cve-2026-18503-lab
scripts/run_target.sh vuln 127.0.0.1 8000
# terminal B
cd cve-2026-18503-lab
python3 exploit/exploit.py --host 127.0.0.1 --port 8000 --n 6000
```

The exploit should report `DENIAL OF SERVICE REPRODUCED`. Stop Terminal A with
`Ctrl+C`, then demonstrate the remediation with the **same** Terminal B command:

```bash
# terminal A: start the remediated target
cd cve-2026-18503-lab
scripts/run_target.sh fixed 127.0.0.1 8000

# terminal B: show remediation is effective
cd cve-2026-18503-lab
python3 exploit/exploit.py --host 127.0.0.1 --port 8000 --n 6000
```

The remediated run should report `Service stayed responsive`.

Turn the knob: `--n` controls payload size and therefore how long the vulnerable
server hangs. Timing depends on the machine; run the benchmark first and choose
a payload that keeps the live demonstration within the assessment time.

## Run it in a Kali Linux VM

The default Kali demonstration uses **one isolated Kali VM and two terminals**:
Terminal 1 is the target service and Terminal 2 is the penetration-testing
terminal. The service intentionally binds to `127.0.0.1`, so this is the
supported setup for the commands below. Kali ships Python 3, so there is
nothing to install:

```bash
cd ~/cve-2026-18503-lab
chmod +x scripts/*.sh
scripts/setup_kali.sh            # verify Python 3 and print the run steps
```

Copy the folder into the VM using a shared folder, `scp`, or a repository clone,
then run the following in two terminals.

Terminal 1 — vulnerable target service:

```bash
cd ~/cve-2026-18503-lab
scripts/run_target.sh vuln 127.0.0.1 8000
```

Terminal 2 — local penetration test:

```bash
cd ~/cve-2026-18503-lab
python3 exploit/exploit.py --host 127.0.0.1 --port 8000 --n 6000
```

The expected result is `[VERDICT] DENIAL OF SERVICE REPRODUCED`. Stop Terminal 1
with `Ctrl+C`, restart it with `MODE=fixed`, and run the same Terminal 2 command
to show `[VERDICT] Service stayed responsive`.

The one-shot helper is also available. It returns `2` when the DoS is reproduced,
`0` when the fixed service remains healthy, and `1` if the target cannot start.

```bash
scripts/run_local.sh vuln 8000 6000
scripts/run_local.sh fixed 8000 6000
```

These commands are for individual same-VM testing. For the consolidated dual-VM
demonstration, see [`DEMO-TWO-VM.md`](DEMO-TWO-VM.md). It uses the same target
launcher with a host-only interface; do not expose the vulnerable service to a
bridged or public network.

## (Optional) Real vulnerable CPython via Docker

Proves the CVE against the genuine standard library, not the vendored copy:

```bash
cd cve-2026-18503-lab
docker compose -f docker/docker-compose.yml up --build
python3 exploit/exploit.py --port 8000   # python:3.12.0  -> DoS reproduced
python3 exploit/exploit.py --port 8001   # python:3.12.14 -> harmless (patched)
```

## Remediation summary

| Layer | Change | Type |
|------|--------|------|
| 1 | Non-backtracking regex `(?:(?P=quote){2}|(?!(?P=quote)).)*+` | **Remediation** (removes the threat) |
| 2 | Cap the sniff sample to 8 KiB | Mitigation (bounds impact) |
| — | Upgrade CPython to 3.10.21 / 3.11.16 / 3.12.14 / 3.13.15 / 3.14.7+ | **Remediation** (operator action) |

See [`report/REPORT.md`](cve-2026-18503-lab/report/REPORT.md) for the full write-up.
