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
import textwrap
import tomllib

ID_RE = re.compile(r"^[a-z0-9-]+(\.[a-z0-9-]+)+$")

REPETITION_RE = re.compile(r"^\d+(,\d*)?\}")

# `generic-api-key` is the one rule dropped on purpose. It is a generic matcher
# behind a 3.5 entropy floor that overlaps every rule in
# `rules/default/generic.yaml`, which was written and tuned against the
# detection corpus to cover the same ground more narrowly. Importing it would
# report every credential those rules already own a second time. The two rules
# once dropped beside it for size, `pypi-upload-token` and `vault-batch-token`,
# are translated as of siloscan's raised regex size limit (see
# `PATTERN_SIZE_LIMIT` in crates/siloscan-core/src/rules.rs).
MANUAL_SKIPS = {
    "generic-api-key": (
        "deliberately excluded: rules/default/generic.yaml covers the same "
        "generic shapes with narrower patterns, and importing this would "
        "double-report every credential they overlap"
    ),
}

# Patterns rewritten narrower on the way in, by rule id.
#
# Go's regexp/syntax reads `\w` as ASCII `[0-9A-Za-z_]`; Rust's reads it as the
# Unicode word class, which is thousands of ranges wide. That difference is
# free almost everywhere and ruinous inside a wide bounded repetition: with the
# Unicode class, `pypi-upload-token`'s program measures 64 MiB and takes
# seconds to build, against 1 MiB and under a millisecond for the ASCII
# spelling the upstream rule actually means. Both rules here are ASCII token
# formats, so the rewrite loses nothing they could match and restores the
# upstream semantics exactly.
#
# Each entry is (search, replacement, reason). The reason is written into the
# generated rule.
ASCII_WORD_REASON = (
    "\\w narrowed to its ASCII form: gitleaks reads \\w as [0-9A-Za-z_] (RE2), "
    "while Rust reads it as the Unicode word class, whose program inside this "
    "repetition exceeds the pattern size limit"
)
NARROW_REWRITES = {
    "pypi-upload-token": (r"[\w-]", r"[0-9A-Za-z_-]", ASCII_WORD_REASON),
    "vault-batch-token": (r"[\w-]", r"[0-9A-Za-z_-]", ASCII_WORD_REASON),
}

# Capture group to report as the secret, for rules that do not set
# `secretGroup` but are written as though gitleaks did.
#
# gitleaks reports capture group 1 when a rule has one, and its allowlists,
# stopwords and entropy floor are all measured against that. siloscan reports
# the whole match unless a rule sets `group`, and the translation carries
# `secretGroup` across and nothing else - so a rule whose allowlist is anchored
# on the captured value alone (`^\%\S.*\%$`) cannot match the whole match and
# stands down on nothing. Verified against gitleaks v8.30.1 on
# `<add key="ClearTextPassword" value="%NUGET_FEED_PAT%" />`: gitleaks reports
# nothing, and siloscan without this entry reports the line.
#
# Only the rules where the difference changes what is reported are listed. The
# general case - 152 of the 221 translated rules have exactly one capture group
# and no `secretGroup` - is a wider question about what the pack reports as the
# match text, and is not this table's business.
SECRET_GROUPS = {
    "nuget-config-password": 1,
}

# Regex metacharacters. A path constraint may only contain them escaped, or in
# the few structural forms `path_globs` understands.
META = set(r".^$*+?()[]{}|\/")

# The one anchor prefix a gitleaks path constraint opens with in v8.30.1, and
# what it costs in translation: `(?:^|\/)[^\/]+` says "a basename with at least
# one character before the suffix", and a glob `*` matches none of them too.
BASENAME_ANCHOR = r"(?:^|\/)[^\/]+"
BASENAME_ANCHOR_WIDENING = "a file whose entire name is the suffix now matches too"

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


def literal_text(pattern):
    """The exact string `pattern` matches, or None when it is not literal.

    A metacharacter is literal only when escaped, so `\\.` is a dot and a bare
    `.` is a construct this translator refuses to guess at.
    """
    out = []
    index = 0
    while index < len(pattern):
        char = pattern[index]
        if char == "\\":
            following = pattern[index + 1 : index + 2]
            if following not in META:
                return None
            out.append(following)
            index += 2
        elif char in META:
            return None
        else:
            out.append(char)
            index += 1
    return "".join(out)


def suffix_alternatives(pattern):
    """Expand a literal path suffix regex into the strings it matches.

    Handles exactly what gitleaks path constraints are made of: literal
    characters, escaped metacharacters, non-capturing alternations of literals
    (`(?:tf|hcl)`) and an optional literal character (`a?`). Returns None on
    anything else, so a construct nobody has translated is a recorded skip
    rather than a glob that quietly means something different.
    """
    # Every position is a set of alternatives; the suffixes are their product.
    positions = []
    index = 0
    length = len(pattern)

    while index < length:
        char = pattern[index]

        if char == "(":
            group = pattern[index:]
            close = group.find(")")
            if not group.startswith("(?:") or close < 0:
                return None
            alternatives = []
            for alternative in group[3:close].split("|"):
                literal = literal_text(alternative)
                if literal is None:
                    return None
                alternatives.append(literal)
            positions.append(alternatives)
            index += close + 1
        else:
            step = 2 if char == "\\" else 1
            literal = literal_text(pattern[index : index + step])
            if literal is None:
                return None
            positions.append([literal])
            index += step

        # A `?` applies to whatever was just read, which for these patterns is
        # always a single literal character.
        if pattern[index : index + 1] == "?":
            if len(positions[-1]) != 1:
                return None
            positions[-1] = positions[-1] + [""]
            index += 1

    suffixes = [""]
    for alternatives in positions:
        suffixes = [prefix + alt for prefix in suffixes for alt in alternatives]
    return sorted(set(suffixes))


def path_globs(pattern):
    """Translate a gitleaks path regex into siloscan globs.

    Returns `(globs, case_insensitive, widenings)`, or None when the regex is
    not one of the shapes this understands. gitleaks matches a path regex
    unanchored against the whole relative path, so a constraint that ends in
    `$` and is otherwise literal is a suffix test, and `**/*<suffix>` is the
    same test written as a glob: `*` does not cross a `/`, and a leading `**/`
    matches any number of leading directories including none.

    `widenings` names every way the globs match more than the regex did. They
    are recorded in the generated rule rather than silently accepted.
    """
    rest = pattern
    case_insensitive = False
    widenings = []

    if rest.startswith("(?i)"):
        case_insensitive = True
        rest = rest[4:]

    if not rest.endswith("$"):
        return None
    rest = rest[:-1]

    if rest.startswith(BASENAME_ANCHOR):
        rest = rest[len(BASENAME_ANCHOR) :]
        widenings.append(BASENAME_ANCHOR_WIDENING)

    suffixes = suffix_alternatives(rest)
    if not suffixes:
        return None

    return ["**/*" + suffix for suffix in suffixes], case_insensitive, widenings


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

    if gid in MANUAL_SKIPS:
        log_skip("rule", gid, MANUAL_SKIPS[gid])
        return None

    rule_id = "secrets." + gid.lower()
    if not ID_RE.match(rule_id):
        log_skip("rule", gid, f"id {rule_id!r} does not match {ID_RE.pattern}")
        return None

    paths = None
    comments = []
    if "path" in rule:
        translated = path_globs(rule["path"])
        if translated is None:
            log_skip("rule", gid, f"path regex {rule['path']!r} has no glob translation")
            return None
        globs, case_insensitive, widenings = translated
        paths = {"include": globs, "case_insensitive": case_insensitive}
        comments.append(f"gitleaks path constraint: {rule['path']}")
        for widening in widenings:
            comments.append(f"widened by the glob translation: {widening}")

    if "regex" not in rule:
        # A path-only gitleaks rule is a siloscan presence rule: no payload
        # block, and the file existing where `paths.include` points is the
        # finding. It fires on binary files too, which is the point for a
        # keystore.
        if paths is None:
            log_skip("rule", gid, "no regex and no path; nothing to match on")
            return None
        return {
            "id": rule_id,
            "severity": "error",
            "message": rule["description"],
            "paths": paths,
            "comments": comments,
        }

    pattern = rule["regex"]
    if gid in NARROW_REWRITES:
        search, replacement, reason = NARROW_REWRITES[gid]
        if search not in pattern:
            log_skip("rule", gid, f"narrowing rewrite {search!r} no longer applies")
            return None
        pattern = pattern.replace(search, replacement)
        comments.append(f"narrowed on import: {reason}")

    construct = unsupported_construct(pattern)
    if construct:
        log_skip("rule", gid, f"{construct} is not supported by the regex engine")
        return None

    secret = {"pattern": pattern}

    group = rule.get("secretGroup", SECRET_GROUPS.get(gid))
    if group is not None:
        secret["group"] = group
        if gid in SECRET_GROUPS:
            comments.append(
                "reports capture group %d, which is the value gitleaks reports "
                "and the value this rule's allowlist is written against" % group
            )

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
        "paths": paths,
        "comments": comments,
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
        for comment in rule.get("comments", []):
            for line in textwrap.wrap(comment, 76, subsequent_indent="  "):
                out.append(f"  # {line}")
        out.append(f"  - id: {rule['id']}")
        out.append(f"    severity: {rule['severity']}")
        out.append(f"    message: {quote(rule['message'])}")
        if rule.get("paths"):
            paths = rule["paths"]
            out.append("    paths:")
            if paths["case_insensitive"]:
                out.append("      case_insensitive: true")
            emit_list(out, "      ", "include", paths["include"])
        if "secret" not in rule:
            continue
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
