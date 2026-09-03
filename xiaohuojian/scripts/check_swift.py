#!/usr/bin/env python3
"""Sanity-check Swift sources: exist, non-empty, roughly balanced braces."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PAIRS = {"{": "}", "(": ")", "[": "]"}
OPEN = set(PAIRS)
CLOSE = {v: k for k, v in PAIRS.items()}


def check_file(path: Path) -> list[str]:
    errs: list[str] = []
    text = path.read_text(encoding="utf-8")
    if not text.strip():
        return ["empty"]
    # strip strings and comments roughly
    cleaned = []
    i = 0
    n = len(text)
    while i < n:
        if text.startswith("//", i):
            i = text.find("\n", i)
            if i < 0:
                break
            continue
        if text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
            continue
        ch = text[i]
        if ch in "\"'":
            q = ch
            i += 1
            while i < n:
                if text[i] == "\\":
                    i += 2
                    continue
                if text[i] == q:
                    i += 1
                    break
                i += 1
            continue
        cleaned.append(ch)
        i += 1
    s = "".join(cleaned)
    stack: list[str] = []
    for ch in s:
        if ch in OPEN:
            stack.append(ch)
        elif ch in CLOSE:
            if not stack or stack[-1] != CLOSE[ch]:
                errs.append(f"unbalanced '{ch}'")
                break
            stack.pop()
    else:
        if stack:
            errs.append(f"unclosed {stack[-8:]}")
    return errs


def main() -> int:
    files = sorted(ROOT.rglob("*.swift"))
    files = [p for p in files if ".git" not in p.parts]
    if not files:
        print("NO SWIFT FILES")
        return 1
    bad = 0
    print(f"Swift files: {len(files)}")
    for p in files:
        rel = p.relative_to(ROOT).as_posix()
        errs = check_file(p)
        status = "OK" if not errs else "FAIL " + "; ".join(errs)
        print(f"  {rel}  ({p.stat().st_size} bytes)  {status}")
        if errs:
            bad += 1
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
