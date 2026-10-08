"""保存可复现的 unittest 结果摘要，且不打印任何秘密输入。"""
import json
from pathlib import Path
import unittest


def main():
    out = Path("results")
    out.mkdir(exist_ok=True)
    suite = unittest.defaultTestLoader.discover(".", pattern="test_protocols.py")
    with (out / "tests.log").open("w", encoding="utf-8") as stream:
        result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
    summary = {"test_methods": result.testsRun, "failures": len(result.failures),
               "errors": len(result.errors), "skipped": len(result.skipped),
               "successful": result.wasSuccessful(),
               "exhaustive_input_pairs": 25, "exhaustive_protocol_runs": 50,
               "note": "Subtests are included in their test method, not counted as independent methods. Security is not established by correctness tests."}
    (out / "tests.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False))
    if not result.wasSuccessful():
        print((out / "tests.log").read_text(encoding="utf-8"))
        raise SystemExit(1)


if __name__ == "__main__":
    main()
