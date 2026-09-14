#!/usr/bin/env python3
"""Run a complete, disjoint share of the native Apple package's race tests."""

import argparse
import re
import subprocess

PACKAGE = "./internal/mdm/apple"


def inventory():
    result = subprocess.run(
        ["go", "test", "-list", ".", PACKAGE],
        check=True, text=True, stdout=subprocess.PIPE,
    )
    names = sorted(
        line for line in result.stdout.splitlines()
        if re.fullmatch(r"(?:Test|Fuzz|Example)[A-Za-z0-9_]*", line)
    )
    if not names or len(names) != len(set(names)):
        raise RuntimeError("Apple test inventory is empty or ambiguous")
    return names


def partition(names, index, count):
    if not 1 <= count <= 16 or not 0 <= index < count or count > len(names):
        raise ValueError("invalid Apple test partition")
    return names[index::count]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--index", type=int, required=True)
    parser.add_argument("--count", type=int, required=True)
    options = parser.parse_args()
    names = inventory()
    selected = partition(names, options.index, options.count)
    print(f"Apple shard {options.index + 1}/{options.count}: "
          f"{len(selected)}/{len(names)} tests and fuzz seed suites", flush=True)
    pattern = "^(" + "|".join(re.escape(name) for name in selected) + ")$"
    subprocess.run(
        ["go", "test", "-race", "-count=1", "-timeout=20m",
         "-run=" + pattern, PACKAGE], check=True,
    )


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as error:
        # The Go command already reports its failure. Do not repeat a multi-KiB
        # selection expression in a Python traceback.
        raise SystemExit(error.returncode) from None
