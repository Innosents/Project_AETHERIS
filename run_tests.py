"""
GraphPath Unified Test Suite Runner (Clean Package Layout)
"""

import sys
import unittest
import argparse
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT_DIR))

def run_suite(suite_name: str = "all", verbosity: int = 2) -> bool:
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    test_modules = []
    if suite_name in ("all", "unit"):
        test_modules.extend([
            # Add test modules as they are ported into tests/
        ])

    print("=" * 70)
    print(f"  GraphPath Test Runner — Executing [{suite_name.upper()}] Suite")
    print("=" * 70)

    if not test_modules:
        print("  [!] No test modules registered yet. Ready for test implementation.")
        return True

    runner = unittest.TextTestRunner(verbosity=verbosity)
    result = runner.run(suite)
    return result.wasSuccessful()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="GraphPath Test Runner")
    parser.add_argument("--suite", choices=["all", "unit"], default="all")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    success = run_suite(suite_name=args.suite, verbosity=2 if args.verbose else 1)
    sys.exit(0 if success else 1)