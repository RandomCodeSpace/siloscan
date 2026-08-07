#!/usr/bin/env python3
"""Parity harness: siloscan secret rules vs gitleaks (issue #50).

Downloads a checksum-pinned gitleaks release binary, runs both scanners over
one or more target directories, joins findings by (file, line), and writes one
TSV of deltas per target with columns:

    file  line  gitleaks_rule  siloscan_rule  bucket

Buckets:
    siloscan-missing     gitleaks fired on the line, siloscan did not
    siloscan-extra       siloscan fired on the line, gitleaks did not
    both-different-rule  both fired, no rule name in common after
                         stripping siloscan's "secrets." prefix
    agree                both fired with a matching rule name; counted in the
                         summary, not listed in the TSV

Manual tooling. Never wired into PR CI. Stdlib only.

Usage:
    parity_gitleaks.py TARGET [TARGET ...] [--siloscan PATH] [--out-dir DIR]
                       [--cache-dir DIR] [--rule-prefix PREFIX]
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

GITLEAKS_VERSION = "8.30.1"
# sha256 of gitleaks_8.30.1_linux_x64.tar.gz, verified 2026-08-07 against
# gitleaks_8.30.1_checksums.txt on the official GitHub release.
GITLEAKS_SHA256 = "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"
GITLEAKS_URL = (
    "https://github.com/gitleaks/gitleaks/releases/download/"
    "v{v}/gitleaks_{v}_linux_x64.tar.gz".format(v=GITLEAKS_VERSION)
)

DEFAULT_CACHE_DIR = os.path.join(
    os.path.expanduser("~"), ".cache", "siloscan-parity"
)

BUCKETS = ("siloscan-missing", "siloscan-extra", "both-different-rule", "agree")


def die(msg):
    print("error: %s" % msg, file=sys.stderr)
    sys.exit(2)


def ensure_gitleaks(cache_dir):
    """Return the path to a verified gitleaks binary, downloading if needed."""
    bin_dir = os.path.join(cache_dir, "gitleaks-%s" % GITLEAKS_VERSION)
    bin_path = os.path.join(bin_dir, "gitleaks")
    if os.access(bin_path, os.X_OK):
        return bin_path

    os.makedirs(bin_dir, exist_ok=True)
    print("downloading gitleaks v%s ..." % GITLEAKS_VERSION, file=sys.stderr)
    fd, archive = tempfile.mkstemp(suffix=".tar.gz", dir=bin_dir)
    try:
        with os.fdopen(fd, "wb") as out, urllib.request.urlopen(
            GITLEAKS_URL
        ) as resp:
            shutil.copyfileobj(resp, out)

        digest = hashlib.sha256()
        with open(archive, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                digest.update(chunk)
        actual = digest.hexdigest()
        if actual != GITLEAKS_SHA256:
            die(
                "gitleaks archive checksum mismatch:\n"
                "  expected %s\n  actual   %s\n"
                "refusing to run an unverified binary"
                % (GITLEAKS_SHA256, actual)
            )

        with tarfile.open(archive, "r:gz") as tar:
            member = tar.getmember("gitleaks")
            if not member.isfile():
                die("gitleaks archive entry is not a regular file")
            src = tar.extractfile(member)
            tmp_bin = bin_path + ".tmp"
            with open(tmp_bin, "wb") as dst:
                shutil.copyfileobj(src, dst)
        # Owner-only: this is a private cache, and nothing but this script
        # needs to read or run the binary.
        os.chmod(tmp_bin, 0o700)
        os.replace(tmp_bin, bin_path)
    finally:
        if os.path.exists(archive):
            os.unlink(archive)
    return bin_path


def run_gitleaks(bin_path, target):
    """Run gitleaks detect --no-git over target.

    Returns a list of (relative_path, line, rule_id).
    """
    fd, report = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    try:
        proc = subprocess.run(
            [
                bin_path,
                "detect",
                "--no-git",
                "--source",
                target,
                "--report-format",
                "json",
                "--report-path",
                report,
                "--exit-code",
                "0",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        if proc.returncode != 0:
            die(
                "gitleaks failed on %s (exit %d):\n%s"
                % (target, proc.returncode, proc.stderr.strip())
            )
        with open(report, encoding="utf-8") as f:
            findings = json.load(f)
    finally:
        os.unlink(report)

    rows = []
    for f in findings:
        path = f["File"]
        rel = os.path.relpath(path, target)
        if rel.startswith(".."):
            rel = path
        rows.append((rel, int(f["StartLine"]), f["RuleID"]))
    return rows


def run_siloscan(bin_path, target, rule_prefix):
    """Run siloscan --format json over target.

    Returns a list of (relative_path, line, rule_id), restricted to rules
    matching rule_prefix (gitleaks parity only makes sense for secret rules).
    """
    proc = subprocess.run(
        [bin_path, target, "--format", "json"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    # 0 = clean, 1 = findings; anything else is a scan failure.
    if proc.returncode not in (0, 1):
        die(
            "siloscan failed on %s (exit %d):\n%s"
            % (target, proc.returncode, proc.stderr.strip())
        )
    report = json.loads(proc.stdout)
    rows = []
    for f in report.get("findings", []):
        if not f["rule_id"].startswith(rule_prefix):
            continue
        rows.append((f["path"], int(f["line"]), f["rule_id"]))
    return rows


def strip_prefix(rule, prefix):
    return rule[len(prefix):] if rule.startswith(prefix) else rule


def join_findings(gitleaks_rows, siloscan_rows, rule_prefix):
    """Join by (file, line). Returns (delta_rows, bucket_counts).

    delta_rows are (file, line, gitleaks_rule, siloscan_rule, bucket) with
    multiple rules on one line joined by ";". Agree keys are counted only.
    """
    by_key_gl = {}
    for path, line, rule in gitleaks_rows:
        by_key_gl.setdefault((path, line), set()).add(rule)
    by_key_ss = {}
    for path, line, rule in siloscan_rows:
        by_key_ss.setdefault((path, line), set()).add(rule)

    counts = {b: 0 for b in BUCKETS}
    deltas = []
    for key in sorted(set(by_key_gl) | set(by_key_ss)):
        gl = sorted(by_key_gl.get(key, ()))
        ss = sorted(by_key_ss.get(key, ()))
        if gl and not ss:
            bucket = "siloscan-missing"
        elif ss and not gl:
            bucket = "siloscan-extra"
        else:
            ss_normed = {strip_prefix(r, rule_prefix) for r in ss}
            bucket = "agree" if ss_normed & set(gl) else "both-different-rule"
        counts[bucket] += 1
        if bucket != "agree":
            deltas.append(
                (key[0], key[1], ";".join(gl) or "-", ";".join(ss) or "-", bucket)
            )
    return deltas, counts


def write_tsv(path, deltas):
    with open(path, "w", encoding="utf-8") as out:
        out.write("file\tline\tgitleaks_rule\tsiloscan_rule\tbucket\n")
        for row in deltas:
            out.write("%s\t%d\t%s\t%s\t%s\n" % row)


def tsv_name(target):
    base = os.path.basename(os.path.normpath(target)) or "root"
    return re.sub(r"[^A-Za-z0-9._-]+", "_", base) + ".tsv"


def main():
    ap = argparse.ArgumentParser(
        description="Compare siloscan secret findings against gitleaks "
        "v%s over one or more directories." % GITLEAKS_VERSION
    )
    ap.add_argument("targets", nargs="+", help="directories to scan")
    ap.add_argument(
        "--siloscan",
        default="target/release/siloscan",
        help="path to the siloscan binary (default: %(default)s)",
    )
    ap.add_argument(
        "--out-dir",
        default="parity-out",
        help="directory for the per-target delta TSVs (default: %(default)s)",
    )
    ap.add_argument(
        "--cache-dir",
        default=DEFAULT_CACHE_DIR,
        help="cache directory for the gitleaks binary (default: %(default)s)",
    )
    ap.add_argument(
        "--rule-prefix",
        default="secrets.",
        help="siloscan rules compared, by id prefix; the prefix is stripped "
        "before rule-name matching (default: %(default)s)",
    )
    args = ap.parse_args()

    siloscan = os.path.abspath(args.siloscan)
    if not os.access(siloscan, os.X_OK):
        die("siloscan binary not found or not executable: %s" % siloscan)
    for target in args.targets:
        if not os.path.isdir(target):
            die("target is not a directory: %s" % target)

    gitleaks = ensure_gitleaks(os.path.abspath(args.cache_dir))
    os.makedirs(args.out_dir, exist_ok=True)

    print(
        "target\tsiloscan-missing\tsiloscan-extra\tboth-different-rule\t"
        "agree\ttsv"
    )
    for target in args.targets:
        target = os.path.abspath(target)
        gl_rows = run_gitleaks(gitleaks, target)
        ss_rows = run_siloscan(siloscan, target, args.rule_prefix)
        deltas, counts = join_findings(gl_rows, ss_rows, args.rule_prefix)
        tsv_path = os.path.join(args.out_dir, tsv_name(target))
        write_tsv(tsv_path, deltas)
        print(
            "%s\t%d\t%d\t%d\t%d\t%s"
            % (
                target,
                counts["siloscan-missing"],
                counts["siloscan-extra"],
                counts["both-different-rule"],
                counts["agree"],
                tsv_path,
            )
        )


if __name__ == "__main__":
    main()
