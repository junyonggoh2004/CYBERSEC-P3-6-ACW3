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
DEMO-GUIDE-DUAL-VM.md        consolidated dual-VM demonstration guide

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
Terminal 1 is the target service and Terminal 2 is the penetration-testing/exploit
terminal. The service intentionally binds to `127.0.0.1`, so this is the
supported setup for the commands below. Kali imports Python 3, so there is
nothing to install. 

Refer to [`DEMO-KALI.md`](DEMO-KALI.md) for specific setup 
on how to reproduce the vulnerability on Kali VM using SSH

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

Terminal 2 — start exploit:

```bash
cd ~/cve-2026-18503-lab
python3 exploit/exploit.py --host 127.0.0.1 --port 8000 --n 6000
```

The expected result is `[VERDICT] DENIAL OF SERVICE REPRODUCED`. Stop Terminal 1
with `Ctrl+C`, then start remediation with

```bash
scripts/run_target.sh fixed 127.0.0.1 8000
```

Run the exploit again in a 2nd terminal:

```bash
python3 exploit/exploit.py --host 127.0.0.1 --port 8000 --n 6000
```
The expected result for effective remediation is `[VERDICT] Service stayed responsive`.

The one-shot helper is also available. It returns `2` when the DoS is reproduced,
`0` when the fixed service remains healthy, and `1` if the target cannot start.

```bash
scripts/run_local.sh vuln 8000 6000
scripts/run_local.sh fixed 8000 6000
```

These commands are for individual same-VM testing. For the consolidated dual-VM
demonstration, see [`DEMO-GUIDE-DUAL-VM.md`](DEMO-GUIDE-DUAL-VM.md). It uses the same target
launcher with a host-only interface; do not expose the vulnerable service to a
bridged or public network.

To compare vulnerable, corrected, and capped detection timings, run:

```bash
python3 exploit/benchmark.py
```

Expected output has this form. Exact timings vary by machine and background
load; the important result is that the vulnerable `x` value approaches `4` when
the input doubles, while the capped timing stays small.

```text
shape=comma_quote_gap  (lower is better; 'x' = growth vs previous row)

      n     bytes      vuln ms      x     fixed ms      x   capped ms
-----------------------------------------------------------------------
    250      5500        26.28      -         2.51      -        1.681
    500     11000        87.88    3.3         2.89    1.2        2.551
   1000     22000       337.49    3.8         6.24    2.2        2.730
   2000     44000      1376.65    4.1        11.78    1.9        2.446

Interpretation:
  * vuln 'x' ~= 4: when n (input) doubles, the vulnerable scan takes about 
    four times longer. This is quadratic O(n^2) growth caused by the vulnerability.
  * fixed 'x' ~= 2: when n (input) doubles, the corrected scan takes about twice as
    long. This is normal linear O(n) growth.
  * capped ms is the time taken when analysing the first 8 KiB. Input is capped to only 8 KiB.
```

The sample above was recorded with `--sizes 250,500,1000,2000`; the default
command tests larger sizes and prints the same columns.

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
