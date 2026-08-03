#!/usr/bin/env python3
"""Translate a gitleaks TOML config into a siloscan YAML rule pack.

Reads config/gitleaks.toml (any tag) and writes a single `version: 1` rule file
whose rules all use the `secret` payload. Rules relying on gitleaks features
siloscan has no mapping for are skipped; every skip is logged to stderr.

Usage:
    convert_gitleaks.py <gitleaks.toml> --tag <tag> [-o <out.yaml>]
"""

import argparse
import re
import sys
import tomllib

ID_RE = re.compile(r"^[a-z0-9-]+(\.[a-z0-9-]+)+$")

REPETITION_RE = re.compile(r"^\d+(,\d*)?\}")

# Rules the Rust regex crate refuses even though the source is RE2-shaped. Their
# wide bounded repetitions (`{10,150}`, `{50,1000}`, ...) compile past the
# crate's default 10 MiB program size limit.
SIZE_LIMIT_REASON = "compiled regex exceeds the regex crate's default 10 MiB size limit"
MANUAL_SKIPS = {
    "generic-api-key": SIZE_LIMIT_REASON,
    "pypi-upload-token": SIZE_LIMIT_REASON,
    "vault-batch-token": SIZE_LIMIT_REASON,
}

SOURCE_URL = "https://raw.githubusercontent.com/gitleaks/gitleaks/{tag}/config/gitleaks.toml"


def log_skip(kind, rule_id, reason):
    print(f"skip {kind} {rule_id}: {reason}", file=sys.stderr)


def unsupported_construct(pattern):
    """Names the first backtracking-only construct in `pattern`, if any.

    The Rust regex crate has no lookaround, backreferences, atomic groups or
    possessive quantifiers, and unlike RE2 it rejects a `{` that does not open a
    repetition, so any rule using them cannot be loaded. Escapes and character
    classes are tracked so that literals such as `\\*+` are not mistaken for the
    operators they escape.
    """
    index = 0
    length = len(pattern)
    in_class = False

    while index < length:
        char = pattern[index]

        if char == "\\":
            following = pattern[index + 1 : index + 2]
            if not in_class and following.isdigit() and following != "0":
                return "backreference"
            if following == "k":
                return "named backreference"
            index += 2
            continue

        if in_class:
            if char == "]":
                in_class = False
            index += 1
            continue

        if char == "[":
            in_class = True
        elif char == "(" and pattern[index + 1 : index + 2] == "?":
            rest = pattern[index + 2 :]
            if rest[:1] in ("=", "!"):
                return "lookahead"
            if rest[:1] == "<" and rest[1:2] in ("=", "!"):
                return "lookbehind"
            if rest[:1] == ">":
                return "atomic group"
            if rest[:1] == "(":
                return "conditional group"
        elif char in "*+?}" and pattern[index + 1 : index + 2] == "+":
            return "possessive quantifier"
        elif char == "{" and not REPETITION_RE.match(pattern[index + 1 :]):
            return "literal '{' outside a repetition"

        index += 1

    return None


def convert_allowlists(rule_id, entries):
    """Merge gitleaks allowlists into a single siloscan allowlist.

    gitleaks allowlist regexes match the secret by default; `regexTarget`
    retargets them at the whole match or the line, which siloscan cannot
    express. `paths` are regexes, siloscan wants globs. `condition = AND` makes
    the criteria conjunctive, which siloscan cannot express either.
    """
    patterns = []
    stopwords = []

    for entry in entries:
        condition = entry.get("condition", "OR").upper()
        if condition != "OR":
            log_skip("allowlist", rule_id, f"condition = {condition} is unsupported")
            continue

        target = entry.get("regexTarget", "secret")
        regexes = entry.get("regexes", [])
        if regexes:
            if target != "secret":
                log_skip(
                    "allowlist patterns",
                    rule_id,
                    f"regexTarget = {target} is unsupported",
                )
            else:
                for pattern in regexes:
                    construct = unsupported_construct(pattern)
                    if construct:
                        log_skip("allowlist pattern", rule_id, f"{construct} in {pattern!r}")
                    else:
                        patterns.append(pattern)

        if entry.get("paths"):
            log_skip("allowlist paths", rule_id, "gitleaks paths are regexes, not globs")

        stopwords.extend(entry.get("stopwords", []))

    allowlist = {}
    if patterns:
        allowlist["patterns"] = patterns
    if stopwords:
        allowlist["stopwords"] = sorted(set(stopwords))
    return allowlist


def convert_rule(rule):
    """Returns a siloscan rule dict, or None if the rule cannot be translated."""
    gid = rule["id"]

    if "regex" not in rule:
        log_skip("rule", gid, "no regex; path-only rules have no siloscan mapping")
        return None

    if "path" in rule:
        log_skip("rule", gid, "path constraint is a regex; siloscan paths are globs")
        return None

    if gid in MANUAL_SKIPS:
        log_skip("rule", gid, MANUAL_SKIPS[gid])
        return None

    rule_id = "secrets." + gid.lower()
    if not ID_RE.match(rule_id):
        log_skip("rule", gid, f"id {rule_id!r} does not match {ID_RE.pattern}")
        return None

    pattern = rule["regex"]
    construct = unsupported_construct(pattern)
    if construct:
        log_skip("rule", gid, f"{construct} is not supported by the regex engine")
        return None

    secret = {"pattern": pattern}

    group = rule.get("secretGroup")
    if group is not None:
        secret["group"] = group

    entropy = rule.get("entropy")
    if entropy is not None:
        secret["entropy"] = float(entropy)

    keywords = rule.get("keywords")
    if keywords:
        secret["keywords"] = sorted(set(keywords))

    entries = rule.get("allowlists", [])
    if "allowlist" in rule:
        entries = [rule["allowlist"]] + entries
    allowlist = convert_allowlists(gid, entries)
    if allowlist:
        secret["allowlist"] = allowlist

    return {
        "id": rule_id,
        "severity": "error",
        "message": rule["description"],
        "secret": secret,
    }


def quote(value):
    return "'" + value.replace("'", "''") + "'"


def number(value):
    text = repr(float(value))
    return text


def emit_list(out, indent, key, values):
    out.append(f"{indent}{key}:")
    for value in values:
        out.append(f"{indent}  - {quote(value)}")


def emit(rules, tag):
    out = [
        "# Default siloscan secrets pack.",
        "# Generated by scripts/convert_gitleaks.py - do not edit by hand.",
        f"# Source: gitleaks {tag}, config/gitleaks.toml (MIT). See NOTICE.",
        "version: 1",
        "rules:",
    ]

    for rule in rules:
        out.append(f"  - id: {rule['id']}")
        out.append(f"    severity: {rule['severity']}")
        out.append(f"    message: {quote(rule['message'])}")
        out.append("    secret:")
        secret = rule["secret"]
        out.append(f"      pattern: {quote(secret['pattern'])}")
        if "group" in secret:
            out.append(f"      group: {secret['group']}")
        if "entropy" in secret:
            out.append(f"      entropy: {number(secret['entropy'])}")
        if "keywords" in secret:
            emit_list(out, "      ", "keywords", secret["keywords"])
        if "allowlist" in secret:
            out.append("      allowlist:")
            allowlist = secret["allowlist"]
            if "patterns" in allowlist:
                emit_list(out, "        ", "patterns", allowlist["patterns"])
            if "stopwords" in allowlist:
                emit_list(out, "        ", "stopwords", allowlist["stopwords"])

    out.append("")
    return "\n".join(out)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", help="path to gitleaks.toml")
    parser.add_argument("--tag", required=True, help="gitleaks release tag being converted")
    parser.add_argument("-o", "--output", help="output YAML path (default: stdout)")
    args = parser.parse_args()

    with open(args.config, "rb") as handle:
        config = tomllib.load(handle)

    if "allowlist" in config or "allowlists" in config:
        print(
            "skip global allowlist: siloscan rule packs have no global allowlist section",
            file=sys.stderr,
        )

    source = config.get("rules", [])
    converted = []
    for rule in sorted(source, key=lambda r: r["id"]):
        result = convert_rule(rule)
        if result is not None:
            converted.append(result)

    converted.sort(key=lambda r: r["id"])
    text = emit(converted, args.tag)

    if args.output:
        with open(args.output, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
    else:
        sys.stdout.write(text)

    print(
        f"converted {len(converted)} of {len(source)} gitleaks rules "
        f"({len(source) - len(converted)} skipped)",
        file=sys.stderr,
    )
    print(f"source: {SOURCE_URL.format(tag=args.tag)}", file=sys.stderr)


if __name__ == "__main__":
    main()
