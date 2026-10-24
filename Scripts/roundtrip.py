#!/usr/bin/env python3
"""Decompile and recompile every file in a corpus and compare the bytes.

The corpus is https://github.com/tge-was-taken/Atlus-Script-Tools-Assets; its manifest
says which library, format and encoding each file needs.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
from concurrent.futures import ProcessPoolExecutor


def run(cfg, args, cwd, log):
    with open(log, "w") as f:
        done = subprocess.run(cfg["exe"].split() + args, cwd=cwd, stdout=f,
                              stderr=subprocess.STDOUT, timeout=cfg["timeout"])
    return done.returncode == 0


def roundtrip(cfg, entry, workdir):
    binary_ext = "bf" if entry["kind"] == "flow" else "bmd"
    text_ext = "flow" if entry["kind"] == "flow" else "msg"
    common = ["-Matching", "-Library", entry["library"], "-OutFormat", entry["format"]]
    if entry.get("encoding"):
        common += ["-Encoding", entry["encoding"]]

    os.makedirs(workdir, exist_ok=True)
    original = os.path.join(workdir, f"in.{binary_ext}")
    shutil.copyfile(os.path.join(cfg["corpus"], entry["corpus"]), original)

    text = os.path.join(workdir, f"in.{text_ext}")
    if not run(cfg, [f"in.{binary_ext}", "-Decompile"] + common + ["-Out", f"in.{text_ext}"],
               workdir, os.path.join(workdir, "decompile.log")):
        return "DECOMPILE_FAIL", ""
    if not os.path.exists(text):
        return "DECOMPILE_NOOUT", ""

    rebuilt = os.path.join(workdir, f"out.{binary_ext}")
    if not run(cfg, [f"in.{text_ext}", "-Compile"] + common + ["-Out", f"out.{binary_ext}"],
               workdir, os.path.join(workdir, "compile.log")):
        return "COMPILE_FAIL", ""
    if not os.path.exists(rebuilt):
        return "COMPILE_NOOUT", ""

    before = open(original, "rb").read()
    after = open(rebuilt, "rb").read()
    if before == after:
        return "MATCH", ""
    differing = sum(1 for a, b in zip(before, after) if a != b) + abs(len(before) - len(after))
    return "DIFF", f"size {len(before)} vs {len(after)}, {differing} bytes differ"


def one(job):
    cfg, entry = job
    if entry.get("known_bad"):
        return "KNOWN_BAD", entry["corpus"], entry["known_bad"]
    workdir = os.path.join(cfg["workdir"], entry["corpus"].replace("/", "_"))
    try:
        status, detail = roundtrip(cfg, entry, workdir)
    except subprocess.TimeoutExpired:
        status, detail = "TIMEOUT", ""
    if status == "MATCH":
        shutil.rmtree(workdir, ignore_errors=True)
    return status, entry["corpus"], detail


def parse_args():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--corpus", required=True, help="corpus checkout holding manifest.json")
    p.add_argument("--exe", required=True, help="AtlusScriptCompiler command")
    p.add_argument("--workdir", default="roundtrip-work", help="where to keep per file output")
    p.add_argument("--results", help="write one status line per file here")
    p.add_argument("--games", help="comma separated game tags, default all")
    p.add_argument("--sample", type=int, default=1, help="take every Nth file")
    p.add_argument("--offset", type=int, default=0, help="which of the N slices to take")
    p.add_argument("--workers", type=int, default=os.cpu_count() or 4)
    p.add_argument("--timeout", type=int, default=600, help="seconds per compiler run")
    return p.parse_args()


def main():
    args = parse_args()
    entries = json.load(open(os.path.join(args.corpus, "manifest.json")))
    if args.games:
        wanted = args.games.split(",")
        entries = [e for e in entries if e["game"] in wanted]
    if not entries:
        print(f"no corpus entries selected for games: {args.games}", file=sys.stderr)
        return 1
    entries = entries[args.offset % args.sample::args.sample]

    cfg = {"corpus": args.corpus, "exe": args.exe, "workdir": args.workdir,
           "timeout": args.timeout}
    shutil.rmtree(args.workdir, ignore_errors=True)
    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        results = list(pool.map(one, [(cfg, e) for e in entries], chunksize=8))

    if args.results:
        with open(args.results, "w") as f:
            for status, name, detail in results:
                f.write(f"{status}|{name}" + (f"|{detail}" if detail else "") + "\n")

    counts = {}
    for status, _, _ in results:
        counts[status] = counts.get(status, 0) + 1
    print(f"{len(results)} files")
    for status in sorted(counts, key=lambda s: -counts[s]):
        print(f"  {counts[status]:6} {status}")

    bad = [r for r in results if r[0] not in ("MATCH", "KNOWN_BAD")]
    for status, name, detail in bad[:50]:
        print(f"{status} {name} {detail}", file=sys.stderr)
    if len(bad) > 50:
        print(f"and {len(bad) - 50} more", file=sys.stderr)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
