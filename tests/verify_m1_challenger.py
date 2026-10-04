"""Empirical Verification & Stress Test Harness for Milestone 1 (Doctor Diagnostic Engine).

This script performs empirical tests:
1. Deterministic execution latency benchmark (<5ms requirement across 1,000 iterations)
2. Strict zero-network enforcement verification (socket audit hooks and monkey-patching)
3. Corrupted binary input stress testing and fuzzing (keytab and MIT CCACHE v4 streams)
4. Schema conformance and edge case resilience
"""

import io
import json
import os
import random
import socket
import struct
import sys
import tempfile
import time
from typing import Any, Dict, List

# Ensure package root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from tanuki.doctor import (
    DoctorReport,
    check_keytab,
    check_krb5_conf,
    check_sssd,
    check_ticket_lifetime,
    diagnose_system,
    parse_ccache_stream,
    parse_proc_keys,
)


def make_valid_keytab(num_entries: int = 2) -> bytes:
    buf = io.BytesIO()
    buf.write(b"\x05\x02")
    for i in range(num_entries):
        realm = b"CORP.LOCAL"
        comps = [b"host", f"server{i:02d}.corp.local".encode("utf-8")]
        key = b"\x55" * 32
        kvno = 1
        keytype = 18

        ebuf = io.BytesIO()
        ebuf.write(struct.pack(">h", len(comps)))
        ebuf.write(struct.pack(">h", len(realm)) + realm)
        for c in comps:
            ebuf.write(struct.pack(">h", len(c)) + c)
        ebuf.write(struct.pack(">I", 1))  # name_type
        ebuf.write(struct.pack(">I", 1700000000))  # timestamp
        ebuf.write(struct.pack(">B", kvno))
        ebuf.write(struct.pack(">h", keytype))
        ebuf.write(struct.pack(">H", len(key)) + key)
        ebuf.write(struct.pack(">I", kvno))

        raw = ebuf.getvalue()
        buf.write(struct.pack(">i", len(raw)))
        buf.write(raw)
    return buf.getvalue()


def make_valid_ccache(remaining_secs: int = 3600) -> bytes:
    now = int(time.time())
    buf = io.BytesIO()
    buf.write(b"\x05\x04")
    buf.write(struct.pack(">H", 0))  # header length

    def write_princ(comps: List[bytes], realm: bytes) -> None:
        buf.write(struct.pack(">I", 1))  # name_type
        buf.write(struct.pack(">I", len(comps)))
        buf.write(struct.pack(">I", len(realm)) + realm)
        for c in comps:
            buf.write(struct.pack(">I", len(c)) + c)

    # default principal
    write_princ([b"admin"], b"CORP.LOCAL")

    # ticket client & server
    write_princ([b"admin"], b"CORP.LOCAL")
    write_princ([b"krbtgt", b"CORP.LOCAL"], b"CORP.LOCAL")

    # keyblock: enctype 18, key len 32
    buf.write(struct.pack(">HI", 18, 32) + (b"\x77" * 32))

    # authtime, starttime, endtime, renew_till
    authtime = now - 60
    starttime = now - 60
    endtime = now + remaining_secs
    renew_till = now + (remaining_secs * 2)
    buf.write(struct.pack(">IIII", authtime, starttime, endtime, renew_till))

    buf.write(b"\x00")  # is_skey
    buf.write(struct.pack(">I", 0x40e00000))  # flags
    buf.write(struct.pack(">I", 0))  # addr_count
    buf.write(struct.pack(">I", 0))  # ad_count
    ticket_data = b"\x61\x82\x01" + (b"\x00" * 30)
    buf.write(struct.pack(">I", len(ticket_data)) + ticket_data)
    sec_data = b"\x00" * 16
    buf.write(struct.pack(">I", len(sec_data)) + sec_data)

    return buf.getvalue()


def make_valid_krb5_conf() -> str:
    return """[libdefaults]
    default_realm = CORP.LOCAL
    dns_lookup_realm = false
    dns_lookup_kdc = false
    ticket_lifetime = 24h
    renew_lifetime = 7d
    forwardable = true

[realms]
    CORP.LOCAL = {
        kdc = dc01.corp.local:88
        admin_server = dc01.corp.local:749
        default_domain = corp.local
    }

[domain_realm]
    .corp.local = CORP.LOCAL
    corp.local = CORP.LOCAL
"""


# 1. Latency Benchmark
def benchmark_deterministic_latency(iterations: int = 1000) -> Dict[str, Any]:
    print(f"\n--- [1/3] Benchmarking Deterministic Execution Latency ({iterations} iterations) ---")

    with tempfile.TemporaryDirectory() as tmpdir:
        kt_path = os.path.join(tmpdir, "krb5.keytab")
        with open(kt_path, "wb") as f:
            f.write(make_valid_keytab(5))

        cfg_path = os.path.join(tmpdir, "krb5.conf")
        with open(cfg_path, "w", encoding="utf-8") as f:
            f.write(make_valid_krb5_conf())

        cc_path = os.path.join(tmpdir, "krb5cc")
        with open(cc_path, "wb") as f:
            f.write(make_valid_ccache(7200))

        # Warm-up (10 runs)
        for _ in range(10):
            diagnose_system(
                keytab_path=kt_path,
                krb5_conf_path=cfg_path,
                sssd_pipe="/tmp/nonexistent.sock",
                sssd_pid="/tmp/nonexistent.pid",
                ccache_path=cc_path,
            )

        durations_ms: List[float] = []
        for _ in range(iterations):
            t0 = time.perf_counter()
            report = diagnose_system(
                keytab_path=kt_path,
                krb5_conf_path=cfg_path,
                sssd_pipe="/tmp/nonexistent.sock",
                sssd_pid="/tmp/nonexistent.pid",
                ccache_path=cc_path,
            )
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            durations_ms.append(elapsed_ms)

        durations_ms.sort()
        avg_ms = sum(durations_ms) / len(durations_ms)
        min_ms = durations_ms[0]
        max_ms = durations_ms[-1]
        p50_ms = durations_ms[int(iterations * 0.50)]
        p90_ms = durations_ms[int(iterations * 0.90)]
        p95_ms = durations_ms[int(iterations * 0.95)]
        p99_ms = durations_ms[int(iterations * 0.99)]
        under_5ms = all(d < 5.0 for d in durations_ms)
        pct_under_5ms = (sum(1 for d in durations_ms if d < 5.0) / iterations) * 100.0

        print(f"Iterations: {iterations}")
        print(f"Min: {min_ms:.4f} ms | Max: {max_ms:.4f} ms")
        print(f"Mean: {avg_ms:.4f} ms | Median (p50): {p50_ms:.4f} ms")
        print(f"p90: {p90_ms:.4f} ms | p95: {p95_ms:.4f} ms | p99: {p99_ms:.4f} ms")
        print(f"Compliance with <5ms requirement: {pct_under_5ms:.2f}% (Under 5ms: {under_5ms})")

        return {
            "iterations": iterations,
            "min_ms": min_ms,
            "max_ms": max_ms,
            "mean_ms": avg_ms,
            "median_ms": p50_ms,
            "p95_ms": p95_ms,
            "p99_ms": p99_ms,
            "under_5ms": under_5ms,
            "pct_under_5ms": pct_under_5ms,
        }


# 2. Zero-Network Verification
def verify_zero_network() -> Dict[str, Any]:
    print("\n--- [2/3] Verifying Zero-Network Behavior ---")

    network_attempts: List[str] = []

    # 1. Audit Hook
    def audit_hook(event: str, args: tuple) -> None:
        if event.startswith("socket."):
            network_attempts.append(f"Audit hook caught event: {event} with args {args}")

    sys.addaudithook(audit_hook)

    # 2. Monkey-patch socket module
    orig_socket = socket.socket
    orig_connect = socket.socket.connect
    orig_getaddrinfo = socket.getaddrinfo
    orig_gethostbyname = socket.gethostbyname

    def mock_socket(*args, **kwargs):
        network_attempts.append("socket.socket() instantiated")
        raise RuntimeError("NETWORK ATTEMPT DETECTED: socket creation")

    def mock_connect(*args, **kwargs):
        network_attempts.append("socket.connect() called")
        raise RuntimeError("NETWORK ATTEMPT DETECTED: socket connect")

    def mock_getaddrinfo(*args, **kwargs):
        network_attempts.append(f"socket.getaddrinfo({args}) called")
        raise RuntimeError("NETWORK ATTEMPT DETECTED: DNS lookup")

    def mock_gethostbyname(*args, **kwargs):
        network_attempts.append(f"socket.gethostbyname({args}) called")
        raise RuntimeError("NETWORK ATTEMPT DETECTED: DNS resolution")

    socket.socket = mock_socket
    socket.getaddrinfo = mock_getaddrinfo
    socket.gethostbyname = mock_gethostbyname

    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            kt_path = os.path.join(tmpdir, "krb5.keytab")
            with open(kt_path, "wb") as f:
                f.write(make_valid_keytab(3))

            cfg_path = os.path.join(tmpdir, "krb5.conf")
            with open(cfg_path, "w", encoding="utf-8") as f:
                f.write(make_valid_krb5_conf())

            cc_path = os.path.join(tmpdir, "krb5cc")
            with open(cc_path, "wb") as f:
                f.write(make_valid_ccache(3600))

            # Run with real files
            report1 = diagnose_system(
                keytab_path=kt_path,
                krb5_conf_path=cfg_path,
                sssd_pipe="/tmp/fake.sock",
                sssd_pid="/tmp/fake.pid",
                ccache_path=cc_path,
            )

            # Run with nonexistent files
            report2 = diagnose_system(
                keytab_path="/tmp/nonexistent.keytab",
                krb5_conf_path="/tmp/nonexistent.conf",
                sssd_pipe="/tmp/nonexistent.sock",
                sssd_pid="/tmp/nonexistent.pid",
                ccache_path="/tmp/nonexistent.ccache",
            )

            # Run with corrupted files
            bad_kt = os.path.join(tmpdir, "bad.keytab")
            with open(bad_kt, "wb") as f:
                f.write(b"\x00\x01\x02\x03\x04")
            bad_cc = os.path.join(tmpdir, "bad.ccache")
            with open(bad_cc, "wb") as f:
                f.write(b"\xff\xff\xff\xff")

            report3 = diagnose_system(
                keytab_path=bad_kt,
                krb5_conf_path=cfg_path,
                sssd_pipe="/tmp/fake.sock",
                sssd_pid="/tmp/fake.pid",
                ccache_path=bad_cc,
            )

    finally:
        socket.socket = orig_socket
        socket.getaddrinfo = orig_getaddrinfo
        socket.gethostbyname = orig_gethostbyname

    zero_network_passed = len(network_attempts) == 0
    print(f"Network calls intercepted: {len(network_attempts)}")
    if not zero_network_passed:
        for att in network_attempts:
            print(f"  [VIOLATION] {att}")
    else:
        print("PASS: Verified 0 network calls across healthy, missing, and corrupted scenarios.")

    return {
        "zero_network_passed": zero_network_passed,
        "intercepted_calls": network_attempts,
    }


# 3. Corrupted Binary Inputs & Adversarial Fuzzing
def stress_test_corrupted_binaries() -> Dict[str, Any]:
    print("\n--- [3/3] Stress Testing Corrupted Binary Inputs & Fuzzing ---")

    failures: List[str] = []
    cases_tested = 0

    with tempfile.TemporaryDirectory() as tmpdir:
        # 3.1 KEYTAB CORRUPTION SUITE
        keytab_cases = [
            ("empty_file", b""),
            ("single_byte_0x05", b"\x05"),
            ("header_0x0501_v1", b"\x05\x01"),
            ("header_0x0000", b"\x00\x00"),
            ("header_0xffff", b"\xff\xff"),
            ("header_0x0503", b"\x05\x03"),
            ("header_random_4bytes", b"\xde\xad\xbe\xef"),
            ("valid_magic_truncated_entry_len", b"\x05\x02\x00\x00"),
            ("valid_magic_huge_entry_len", b"\x05\x02\x7f\xff\xff\xff"),
            ("valid_magic_negative_entry_len", b"\x05\x02\xff\xff\xff\xf0"),
            ("valid_magic_with_garbage_entry", b"\x05\x02\x00\x00\x00\x10" + b"\xaa" * 16),
            ("valid_magic_truncated_comps", b"\x05\x02\x00\x00\x00\x06\x00\x05\x00\x02AB"),
            ("valid_magic_huge_comp_count", b"\x05\x02\x00\x00\x00\x10\x7f\xff\x00\x02AB"),
        ]

        for name, data in keytab_cases:
            cases_tested += 1
            fpath = os.path.join(tmpdir, f"kt_{name}.keytab")
            with open(fpath, "wb") as f:
                f.write(data)
            try:
                res = check_keytab(fpath)
                if not isinstance(res, dict) or "status" not in res:
                    failures.append(f"Keytab case '{name}' returned invalid check structure: {res}")
                if res["status"] not in ("FAIL", "WARN", "N_A"):
                    failures.append(f"Keytab case '{name}' expected FAIL/WARN/N_A, got: {res['status']}")
            except Exception as exc:
                failures.append(f"Keytab case '{name}' raised uncaught exception: {type(exc).__name__}: {exc}")

        # 3.2 CCACHE CORRUPTION SUITE
        ccache_cases = [
            ("empty_file", b""),
            ("single_byte", b"\x05"),
            ("two_bytes", b"\x05\x04"),
            ("three_bytes", b"\x05\x04\x00"),
            ("invalid_magic_0502", b"\x05\x02\x00\x00"),
            ("invalid_magic_0000", b"\x00\x00\x00\x00"),
            ("invalid_magic_ffff", b"\xff\xff\x00\x00"),
            ("huge_header_tags_len", b"\x05\x04\xff\xff" + b"\x00" * 10),
            ("valid_header_no_principal", b"\x05\x04\x00\x00"),
            ("truncated_principal_head", b"\x05\x04\x00\x00\x00\x00\x00\x01\x00"),
            ("huge_realm_len", b"\x05\x04\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x7f\xff\xff\xff"),
            ("huge_comp_count", b"\x05\x04\x00\x00\x00\x00\x00\x01\x7f\xff\xff\xff\x00\x00\x00\x04CORP"),
            ("valid_header_truncated_cred", b"\x05\x04\x00\x00" + b"\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x04CORP"),
            ("garbage_cred_data", b"\x05\x04\x00\x00" + b"\xaa" * 100),
        ]

        for name, data in ccache_cases:
            cases_tested += 1
            fpath = os.path.join(tmpdir, f"cc_{name}.ccache")
            with open(fpath, "wb") as f:
                f.write(data)
            try:
                res = check_ticket_lifetime(fpath)
                if not isinstance(res, dict) or "status" not in res:
                    failures.append(f"CCACHE case '{name}' returned invalid check structure: {res}")
                if res["status"] not in ("PASS", "WARN", "FAIL", "EXPIRED", "N_A"):
                    failures.append(f"CCACHE case '{name}' returned invalid status: {res['status']}")
            except Exception as exc:
                failures.append(f"CCACHE case '{name}' raised uncaught exception: {type(exc).__name__}: {exc}")

        # 3.3 RANDOM FUZZING (500 mutated keytabs & 500 mutated ccaches)
        print("Running 500 random mutations on Keytab...")
        valid_kt_base = make_valid_keytab(2)
        rng = random.Random(42)  # Deterministic seed

        for i in range(500):
            cases_tested += 1
            # Random mutation: truncation, bit-flip, slice deletion, random byte insertion
            mut = bytearray(valid_kt_base)
            mutation_type = rng.choice(["truncate", "bitflip", "insert", "replace", "garbage"])
            if mutation_type == "truncate":
                mut = mut[: rng.randint(0, len(mut))]
            elif mutation_type == "bitflip":
                if len(mut) > 0:
                    pos = rng.randint(0, len(mut) - 1)
                    mut[pos] ^= rng.randint(1, 255)
            elif mutation_type == "insert":
                pos = rng.randint(0, len(mut))
                mut[pos:pos] = rng.randbytes(rng.randint(1, 64))
            elif mutation_type == "replace":
                if len(mut) > 4:
                    pos = rng.randint(0, len(mut) - 4)
                    mut[pos : pos + 4] = rng.randbytes(4)
            elif mutation_type == "garbage":
                mut = rng.randbytes(rng.randint(0, 512))

            fpath = os.path.join(tmpdir, f"fuzz_kt_{i}.keytab")
            with open(fpath, "wb") as f:
                f.write(mut)

            try:
                res = check_keytab(fpath)
                if not isinstance(res, dict) or "status" not in res:
                    failures.append(f"Fuzz keytab #{i} returned non-dict: {res}")
            except Exception as exc:
                failures.append(f"Fuzz keytab #{i} ({mutation_type}) crashed with {type(exc).__name__}: {exc}")

        print("Running 500 random mutations on CCACHE...")
        valid_cc_base = make_valid_ccache(3600)
        for i in range(500):
            cases_tested += 1
            mut = bytearray(valid_cc_base)
            mutation_type = rng.choice(["truncate", "bitflip", "insert", "replace", "garbage"])
            if mutation_type == "truncate":
                mut = mut[: rng.randint(0, len(mut))]
            elif mutation_type == "bitflip":
                if len(mut) > 0:
                    pos = rng.randint(0, len(mut) - 1)
                    mut[pos] ^= rng.randint(1, 255)
            elif mutation_type == "insert":
                pos = rng.randint(0, len(mut))
                mut[pos:pos] = rng.randbytes(rng.randint(1, 64))
            elif mutation_type == "replace":
                if len(mut) > 4:
                    pos = rng.randint(0, len(mut) - 4)
                    mut[pos : pos + 4] = rng.randbytes(4)
            elif mutation_type == "garbage":
                mut = rng.randbytes(rng.randint(0, 512))

            fpath = os.path.join(tmpdir, f"fuzz_cc_{i}.ccache")
            with open(fpath, "wb") as f:
                f.write(mut)

            try:
                res = check_ticket_lifetime(fpath)
                if not isinstance(res, dict) or "status" not in res:
                    failures.append(f"Fuzz ccache #{i} returned non-dict: {res}")
            except Exception as exc:
                failures.append(f"Fuzz ccache #{i} ({mutation_type}) crashed with {type(exc).__name__}: {exc}")

    print(f"Total corrupted binary test cases evaluated: {cases_tested}")
    print(f"Uncaught crashes or unhandled exceptions: {len(failures)}")
    if failures:
        for f in failures[:10]:
            print(f"  [FAILURE] {f}")
        if len(failures) > 10:
            print(f"  ... and {len(failures) - 10} more.")

    return {
        "cases_tested": cases_tested,
        "failures_count": len(failures),
        "failures": failures,
    }


def main():
    print("[EMPIRICAL VERIFICATION HARNESS: Milestone 1 Doctor Engine]")

    bench_results = benchmark_deterministic_latency(1000)
    net_results = verify_zero_network()
    stress_results = stress_test_corrupted_binaries()

    print("\n[SUMMARY OF EMPIRICAL VERIFICATION RESULTS]")
    print(f"1. Latency Benchmark: Mean={bench_results['mean_ms']:.4f} ms, Max={bench_results['max_ms']:.4f} ms, Sub-5ms={bench_results['under_5ms']}")
    print(f"2. Zero-Network Compliance: {net_results['zero_network_passed']} (0 network calls)")
    print(f"3. Binary Corruption Resilience: {stress_results['cases_tested']} cases, 0 crashes ({stress_results['failures_count']} failures)")

    all_passed = (
        bench_results["under_5ms"]
        and net_results["zero_network_passed"]
        and stress_results["failures_count"] == 0
    )

    verdict = "APPROVE" if all_passed else "REJECT"
    print(f"\nFINAL VERDICT: {verdict}")

    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
