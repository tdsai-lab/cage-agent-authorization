#!/usr/bin/env python3
"""download_ieee_cis.py — fetch the IEEE-CIS Fraud Detection data used by the real-data experiments.

The competition data is licensed and MUST NOT be redistributed, so this artifact ships the fetcher and
the deterministic preprocessing instead of the CSVs. Run:

    python scripts/download_ieee_cis.py --out bridge_benchmark/data/raw/ieee_cis
    export IEEE_CIS_DIR=$PWD/bridge_benchmark/data/raw/ieee_cis

Prerequisites (one time):
  1. pip install kaggle
  2. create an API token (Kaggle account page -> "Create New API Token") -> ~/.kaggle/kaggle.json
  3. open the competition page and ACCEPT THE RULES — the API refuses to serve the files otherwise:
     https://www.kaggle.com/competitions/ieee-fraud-detection/rules

The script verifies the download against the SHA-256 of the exact files used for the reported
numbers, so a successful `--verify` means every downstream result is bit-reproducible.

`--verify-only` checks files you obtained some other way (e.g. an institutional mirror) without
downloading anything.
"""
from __future__ import annotations

import argparse
import hashlib
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

COMPETITION = "ieee-fraud-detection"
RULES_URL = "https://www.kaggle.com/competitions/ieee-fraud-detection/rules"

# the exact files behind the reported results
EXPECTED = {
    "train_transaction.csv": {
        "sha256": "3a5c83ab6b3cc13dcabe5ffa9f522307fd5f7f7b6e6f6a60c32284ca6283d642",
        "bytes": 683351067,
        "lines": 590541,
        "required": True,
    },
    "train_identity.csv": {
        "sha256": "b63c725d8377be90a995268d97f347c17d456b95db45807adcf9f59cd603c37c",
        "bytes": 26529680,
        "lines": 144234,
        "required": False,  # the generator runs without it
    },
}


def sha256_of(path: Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(chunk), b""):
            h.update(block)
    return h.hexdigest()


def count_lines(path: Path, chunk: int = 1 << 20) -> int:
    n = 0
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(chunk), b""):
            n += block.count(b"\n")
    return n


def verify(out: Path, quick: bool = False) -> bool:
    ok = True
    for name, meta in EXPECTED.items():
        p = out / name
        if not p.exists():
            level = "MISSING (required)" if meta["required"] else "missing (optional)"
            print(f"  [{'FAIL' if meta['required'] else 'warn'}] {name}: {level}")
            ok = ok and not meta["required"]
            continue
        size = p.stat().st_size
        if size != meta["bytes"]:
            print(f"  [FAIL] {name}: {size} bytes, expected {meta['bytes']}")
            ok = False
            continue
        if quick:
            print(f"  [ok]   {name}: {size} bytes (size only; drop --quick to hash)")
            continue
        digest = sha256_of(p)
        lines = count_lines(p)
        if digest == meta["sha256"] and lines == meta["lines"]:
            print(f"  [ok]   {name}: sha256 {digest[:16]}…, {lines} lines — matches the reported run")
        else:
            print(f"  [FAIL] {name}: sha256 {digest[:16]}… ({meta['sha256'][:16]}… expected), "
                  f"{lines} lines ({meta['lines']} expected)")
            ok = False
    return ok


def download(out: Path) -> None:
    if shutil.which("kaggle") is None:
        sys.exit("kaggle CLI not found. `pip install kaggle`, then create ~/.kaggle/kaggle.json "
                 f"and accept the competition rules at {RULES_URL}")
    out.mkdir(parents=True, exist_ok=True)
    print(f"downloading competition '{COMPETITION}' into {out} …")
    for name in EXPECTED:
        cmd = ["kaggle", "competitions", "download", "-c", COMPETITION, "-f", name, "-p", str(out)]
        print("  $ " + " ".join(cmd))
        res = subprocess.run(cmd)
        if res.returncode != 0:
            sys.exit(f"kaggle download failed for {name}. The usual cause is not having accepted the "
                     f"competition rules: {RULES_URL}")
    for zp in sorted(out.glob("*.zip")):
        print(f"  unzipping {zp.name}")
        with zipfile.ZipFile(zp) as zf:
            zf.extractall(out)
        zp.unlink()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default="bridge_benchmark/data/raw/ieee_cis",
                    help="destination directory (default: %(default)s)")
    ap.add_argument("--verify-only", action="store_true", help="verify an existing copy, download nothing")
    ap.add_argument("--quick", action="store_true", help="verify sizes only (skip the ~700 MB hash)")
    args = ap.parse_args()

    out = Path(args.out).resolve()
    if not args.verify_only:
        download(out)

    print(f"\nverifying {out}:")
    ok = verify(out, quick=args.quick)
    if not ok:
        sys.exit("\nverification FAILED — the downstream records will not match the reported numbers.")
    print(f"\nOK. Now:  export IEEE_CIS_DIR={out}")
    print("Then see bridge_benchmark/data/README.md for the deterministic record-generation command,")
    print("and REPRODUCE.md §4 for every experiment that uses it.")


if __name__ == "__main__":
    main()
