# Consolidated Demo Runbook - Kali Tester and Target VM

Use this runbook only for the final combined demonstration. It separates the
Kali testing VM from the vulnerable target VM while keeping both machines on an
isolated host-only network.

## 1. Build the isolated network

Configure both virtual machines with a host-only adapter. Do not use bridged
networking or expose the target service to the Internet. Confirm that the Kali VM
can reach only the target VM's private address.

## 2. Prepare the target VM

Copy the lab folder to the target VM and start the vulnerable service. Replace
the example address with the target VM's host-only IP address when you record it.

```bash
cd ~/cve-2026-18503-lab
chmod +x scripts/*.sh
scripts/setup_kali.sh
ip -4 addr
scripts/run_target.sh vuln 0.0.0.0 8000
```

Keep this terminal open. The target is ready when it prints its listening address.

## 3. Prepare Kali and verify reachability

Copy the same lab folder to Kali, then check the target health endpoint before
starting the demonstration.

```bash
cd ~/cve-2026-18503-lab
curl http://<target-private-ip>:8000/health
```

The response must identify `mode` as `vuln`. If it does not, stop and fix the
target setup before the assessment.

## 4. Run the controlled test from Kali

```bash
cd ~/cve-2026-18503-lab
python3 exploit/exploit.py --host <target-private-ip> --port 8000 --n 6000
```

After recording the result, stop the target service with `Ctrl+C`.

## 5. Verify the remediation

On the target VM, restart the service in fixed mode:

```bash
scripts/run_target.sh fixed 0.0.0.0 8000
```

From Kali, repeat the exact same command from Step 4. Record the response time
and health-probe outcome for the before-and-after evidence.

## Pre-demo checklist

- Both VMs use only the host-only network.
- The target service is already running before the assessor arrives.
- Kali can reach `/health` on the private target address.
- The vulnerable and fixed commands have been tested with the same payload size.
- The lab folder, evidence screenshots, and report are available locally.
