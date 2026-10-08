"""正常输出只包含允许公开的比较结果。"""
import argparse
import json
from crypto_utils import generate_key
from protocols import LABELS, Participant, compare_original, compare_ot


def main():
    parser = argparse.ArgumentParser(description="百万富翁问题实验")
    parser.add_argument("--scheme", choices=["original", "ot", "both"], default="both")
    parser.add_argument("--alice", type=int, required=True)
    parser.add_argument("--bob", type=int, required=True)
    parser.add_argument("--domain", type=int, default=10)
    parser.add_argument("--bits", type=int, default=2048)
    parser.add_argument("--metrics", action="store_true", help="also print public performance statistics")
    args = parser.parse_args()
    # 双方输入只是本地模拟配置，绝不通过消息传输。
    from protocols import validate_wealth
    validate_wealth(args.alice, args.domain)
    validate_wealth(args.bob, args.domain)
    schemes = ["original", "ot"] if args.scheme == "both" else [args.scheme]
    alice = Participant("Alice", args.alice, args.domain, generate_key(args.bits))
    bob_key = generate_key(args.bits) if "original" in schemes else None
    bob = Participant("Bob", args.bob, args.domain, bob_key)
    for name in schemes:
        result = (compare_original if name == "original" else compare_ot)(alice, bob)
        print(f"{name}: {LABELS[result.code]}")
        if args.metrics:
            print(json.dumps({"scheme": name, "elapsed_ms": round(result.elapsed_ms, 3),
                              "bytes": result.bytes_sent, "messages": result.messages,
                              "prime_attempts": result.prime_attempts}, ensure_ascii=False))


if __name__ == "__main__":
    main()
