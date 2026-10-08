"""配对输入基准测试；结果中不含任何一方的财富值或财富差值。"""
import argparse
import csv
import json
import platform
import random
import statistics
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
import cryptography
from crypto_utils import generate_key
from protocols import Participant, compare_original, compare_ot


def make_cases(domain, random_cases):
    if domain == 5:
        return [(a, b) for a in range(1, 6) for b in range(1, 6)]
    fixed = [(1, 1), (domain, domain), (1, domain), (domain, 1),
             (domain // 2, domain // 2 + 1), (domain // 2 + 1, domain // 2)]
    rng = random.Random(20261008 + domain)
    return fixed + [(rng.randint(1, domain), rng.randint(1, domain)) for _ in range(random_cases)]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--domains", nargs="+", type=int, default=[5, 10, 25])
    parser.add_argument("--random-cases", type=int, default=9)
    parser.add_argument("--bits", type=int, default=2048)
    parser.add_argument("--output", default="results")
    args = parser.parse_args()
    if any(not 2 <= m <= 10000 for m in args.domains) or args.random_cases < 0:
        parser.error("invalid domain or random case count")
    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    start = time.perf_counter_ns()
    ak = generate_key(args.bits)
    alice_key_ms = (time.perf_counter_ns() - start) / 1e6
    start = time.perf_counter_ns()
    bk = generate_key(args.bits)
    bob_key_ms = (time.perf_counter_ns() - start) / 1e6
    records, aggregates = [], []
    for domain in args.domains:
        cases = make_cases(domain, args.random_cases)
        # 每套方案先跑一次不计时的预热，且不计入正确性统计。
        parties = Participant("Alice", 1, domain, ak), Participant("Bob", domain, domain, bk)
        compare_original(*parties)
        compare_ot(*parties)
        for case_id, (a, b) in enumerate(cases):
            expected = 2 if a > b else 1 if a == b else 0
            parties = Participant("Alice", a, domain, ak), Participant("Bob", b, domain, bk)
            order = [("original", compare_original), ("ot", compare_ot)]
            if case_id % 2:
                order.reverse()
            for name, protocol in order:
                start = time.perf_counter_ns()
                try:
                    result = protocol(*parties)
                    row = {"domain": domain, "case_id": case_id, "scheme": name, "success": True,
                           "correct": result.code == expected, "elapsed_ms": result.elapsed_ms,
                           "bytes": result.bytes_sent, "messages": result.messages,
                           "prime_attempts": result.prime_attempts, "error": ""}
                except Exception as exc:
                    row = {"domain": domain, "case_id": case_id, "scheme": name, "success": False,
                           "correct": False, "elapsed_ms": (time.perf_counter_ns() - start) / 1e6,
                           "bytes": None, "messages": None, "prime_attempts": None,
                           "error": type(exc).__name__}
                records.append(row)
        for name in ("original", "ot"):
            rows = [r for r in records if r["domain"] == domain and r["scheme"] == name]
            successful = [r for r in rows if r["success"]]
            times = [r["elapsed_ms"] for r in rows]
            aggregates.append({"domain": domain, "scheme": name, "cases": len(rows),
                               "correct": sum(r["correct"] for r in rows),
                               "failures": sum(not r["success"] for r in rows),
                               "accuracy": sum(r["correct"] for r in rows) / len(rows),
                               "mean_ms": statistics.mean(times), "median_ms": statistics.median(times),
                               "min_ms": min(times), "max_ms": max(times),
                               "mean_bytes": statistics.mean(r["bytes"] for r in successful) if successful else None,
                               "messages": sorted({r["messages"] for r in successful}),
                               "total_prime_attempts": sum(r["prime_attempts"] for r in successful)})
        print(f"Completed domain={domain}, paired cases={len(cases)}", flush=True)
    report = {"generated_at": datetime.now(timezone(timedelta(hours=8))).isoformat(),
              "environment": {"os": platform.platform(), "processor": platform.processor(),
                              "python": platform.python_version(), "cryptography": cryptography.__version__},
              "parameters": {"rsa_bits": args.bits, "e": 65537, "prime_bits": args.bits // 2,
                             "ot_hash": "SHAKE256", "ot_session_bytes": 16,
                             "max_prime_attempts": 32, "input_seed": 20261008,
                             "random_cases_per_non5_domain": args.random_cases},
              "setup": {"alice_key_ms": alice_key_ms, "bob_key_ms": bob_key_ms,
                        "original_keys_ms": alice_key_ms + bob_key_ms, "ot_keys_ms": alice_key_ms},
              "methodology": {"timing": "complete online three-way comparison; includes fresh randomness, original prime generation, encoding, and final result messages; excludes long-lived RSA key generation",
                              "communication": "actual compact UTF-8 JSON bytes including public keys, envelopes, and result messages; no TCP/TLS headers",
                              "round": "one single-direction serialized message; original=8, OT=4",
                              "inputs": "M=5 exhaustive; other M include six boundaries and deterministic random samples; paired same inputs; execution order alternates",
                              "warmup": "one untimed complete run per scheme and domain"},
              "summary": aggregates, "records": records}
    (out / "benchmark.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    with (out / "benchmark.csv").open("w", newline="", encoding="utf-8-sig") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(records[0]))
        writer.writeheader()
        writer.writerows(records)
    print(json.dumps(aggregates, ensure_ascii=False, indent=2))
    if any(not r["correct"] for r in records):
        raise SystemExit("Benchmark has failures or incorrect results; inspect results")


if __name__ == "__main__":
    main()
