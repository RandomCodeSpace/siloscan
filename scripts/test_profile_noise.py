#!/usr/bin/env python3
"""Deterministic tests for the profile noise measurement.

Run with `python3 -m unittest discover -s scripts -p 'test_profile_*.py'`.
Nothing here clones a repository, runs a binary, or touches the network: this
file exercises the two parsers, the rate arithmetic, the per-rule limit check
and the tables that record them. The one test that reads a real file reads the
committed noise set and the committed limits, both of which are in the tree.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import profile_noise  # noqa: E402

SHA_A = "a" * 40
SHA_B = "b" * 40

NOISE_SET = f"""# Heading

## Rust

| Repository | URL | Tag | Commit | Licence (SPDX) | Licence file path | Files | Bytes | Status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| ripgrep | https://github.com/BurntSushi/ripgrep | 15.2.0 | {SHA_A} | MIT | COPYING | 100 | 1791121 | pinned |

## Go

| Repository | URL | Tag | Commit | Licence (SPDX) | Licence file path | Files | Bytes | Status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| cobra | https://github.com/spf13/cobra | v1.10.2 | {SHA_B} | Apache-2.0 | LICENSE.txt | 36 | 508940 | pinned |

---

## Deviations from Design List

1. Nothing here is a table.
"""

LIMITS = """# a comment
rule_id\tmax_corpus\tmax_per_kloc\tmeasured_at\tticket
reliability.go.err-shadow\t0\t0.5000\t2026-09-03\tP4
reliability.go.nil-deref\t1\t2.0000\t2026-09-03\tP4
"""


def repo(name="cobra", language="go", commit=SHA_B):
    return profile_noise.Repository(
        language=language,
        name=name,
        url=f"https://github.com/example/{name}",
        tag="v1",
        commit=commit,
        licence="MIT",
    )


def result(findings, code_lines=10_000, name="cobra"):
    return profile_noise.Result(
        repo=repo(name=name),
        files_scanned=36,
        code_lines=code_lines,
        elapsed_seconds=1.25,
        findings=findings,
    )


class ParseNoiseSet(unittest.TestCase):
    def test_a_row_is_read_under_the_language_heading_above_it(self):
        parsed = profile_noise.parse_noise_set(NOISE_SET)
        self.assertEqual([r.name for r in parsed], ["ripgrep", "cobra"])
        self.assertEqual([r.language for r in parsed], ["rust", "go"])

    def test_every_pinned_field_survives_the_parse(self):
        cobra = profile_noise.parse_noise_set(NOISE_SET)[1]
        self.assertEqual(cobra.url, "https://github.com/spf13/cobra")
        self.assertEqual(cobra.tag, "v1.10.2")
        self.assertEqual(cobra.commit, SHA_B)
        self.assertEqual(cobra.licence, "Apache-2.0")

    def test_header_and_separator_rows_are_not_repositories(self):
        self.assertEqual(len(profile_noise.parse_noise_set(NOISE_SET)), 2)

    def test_prose_after_the_tables_is_not_a_repository(self):
        self.assertNotIn(
            "Deviations", [r.name for r in profile_noise.parse_noise_set(NOISE_SET)]
        )

    def test_a_short_commit_is_refused(self):
        text = NOISE_SET.replace(SHA_B, "deadbeef")
        with self.assertRaisesRegex(profile_noise.NoiseError, "not a 40-character"):
            profile_noise.parse_noise_set(text)

    def test_an_unpinned_row_is_refused_rather_than_skipped(self):
        text = NOISE_SET.replace("| 508940 | pinned |", "| 508940 | proposed |")
        with self.assertRaisesRegex(profile_noise.NoiseError, "expected pinned"):
            profile_noise.parse_noise_set(text)

    def test_a_row_with_the_wrong_column_count_is_refused(self):
        text = NOISE_SET.replace(
            f"| cobra | https://github.com/spf13/cobra | v1.10.2 | {SHA_B} "
            "| Apache-2.0 | LICENSE.txt | 36 | 508940 | pinned |",
            f"| cobra | https://github.com/spf13/cobra | {SHA_B} | pinned |",
        )
        with self.assertRaisesRegex(profile_noise.NoiseError, "expected 9"):
            profile_noise.parse_noise_set(text)

    def test_a_row_above_every_heading_is_refused(self):
        text = f"| x | https://e/x | v1 | {SHA_A} | MIT | L | 1 | 1 | pinned |\n"
        with self.assertRaisesRegex(profile_noise.NoiseError, "outside a language"):
            profile_noise.parse_noise_set(text)

    def test_a_noise_set_with_no_rows_is_refused(self):
        with self.assertRaisesRegex(profile_noise.NoiseError, "no repositories"):
            profile_noise.parse_noise_set("## Rust\n\nnothing here\n")

    def test_the_committed_noise_set_parses(self):
        parsed = profile_noise.parse_noise_set(
            profile_noise.DEFAULT_NOISE_SET.read_text(encoding="utf-8")
        )
        self.assertEqual(len(parsed), 29)
        self.assertEqual(len({r.commit for r in parsed}), 29)
        self.assertEqual(len({r.language for r in parsed}), 10)


class ParseLimits(unittest.TestCase):
    def test_both_ceilings_are_read(self):
        limits = profile_noise.parse_limits(LIMITS)
        self.assertEqual(limits["reliability.go.err-shadow"].max_corpus, 0)
        self.assertEqual(limits["reliability.go.err-shadow"].max_per_kloc, 0.5)
        self.assertEqual(limits["reliability.go.nil-deref"].max_corpus, 1)
        self.assertEqual(limits["reliability.go.nil-deref"].max_per_kloc, 2.0)

    def test_comments_and_the_header_are_not_rules(self):
        self.assertEqual(len(profile_noise.parse_limits(LIMITS)), 2)

    def test_an_empty_file_is_no_limits_rather_than_an_error(self):
        self.assertEqual(profile_noise.parse_limits(""), {})

    def test_a_rule_named_twice_is_refused(self):
        text = LIMITS + "reliability.go.nil-deref\t0\t1.0\t2026-09-03\tP4\n"
        with self.assertRaisesRegex(profile_noise.NoiseError, "named twice"):
            profile_noise.parse_limits(text)

    def test_a_row_with_the_wrong_field_count_is_refused(self):
        with self.assertRaisesRegex(profile_noise.NoiseError, "expected 5"):
            profile_noise.parse_limits("a.b.c\t0\t1.0\n")

    def test_a_negative_ceiling_is_refused(self):
        with self.assertRaisesRegex(profile_noise.NoiseError, "negative"):
            profile_noise.parse_limits("a.b.c\t0\t-1.0\t2026-09-03\tP4\n")

    def test_a_rule_with_no_row_is_held_to_zero(self):
        limits = profile_noise.parse_limits(LIMITS)
        self.assertEqual(
            profile_noise.limit_for(limits, "reliability.go.unheard-of"),
            profile_noise.DEFAULT_LIMIT,
        )

    def test_the_committed_limits_parse(self):
        profile_noise.parse_limits(
            profile_noise.DEFAULT_LIMITS.read_text(encoding="utf-8")
        )


class Rates(unittest.TestCase):
    def test_a_rate_is_findings_per_thousand_code_lines(self):
        self.assertAlmostEqual(profile_noise.per_kloc(5, 10_000), 0.5)

    def test_a_repository_with_no_code_lines_has_no_rate(self):
        self.assertEqual(profile_noise.per_kloc(3, 0), 0.0)

    def test_no_findings_is_a_rate_of_zero(self):
        self.assertEqual(profile_noise.per_kloc(0, 10_000), 0.0)


class Breaches(unittest.TestCase):
    def setUp(self):
        self.limits = profile_noise.parse_limits(LIMITS)

    def test_a_rate_under_the_ceiling_passes(self):
        found = result({"reliability.go.err-shadow": 4})
        self.assertEqual(profile_noise.breaches([found], self.limits), [])

    def test_the_ceiling_itself_passes(self):
        found = result({"reliability.go.err-shadow": 5})
        self.assertEqual(profile_noise.breaches([found], self.limits), [])

    def test_one_finding_over_the_ceiling_breaches(self):
        found = result({"reliability.go.err-shadow": 6})
        over = profile_noise.breaches([found], self.limits)
        self.assertEqual(len(over), 1)
        self.assertIn("reliability.go.err-shadow", over[0])
        self.assertIn("cobra", over[0])

    def test_a_rule_with_no_declared_limit_breaches_on_its_first_finding(self):
        found = result({"reliability.go.unheard-of": 1})
        self.assertEqual(len(profile_noise.breaches([found], self.limits)), 1)

    def test_the_check_is_per_repository_and_not_a_total(self):
        # Ten findings each over two repositories is 1.0 per kloc each, which is
        # under the 2.0 ceiling. Summed it would be 20 findings and still under;
        # what per-repository catches is the opposite case below.
        quiet = [
            result({"reliability.go.nil-deref": 10}, name="cobra"),
            result({"reliability.go.nil-deref": 10}, name="gin"),
        ]
        self.assertEqual(profile_noise.breaches(quiet, self.limits), [])

    def test_one_noisy_repository_is_not_averaged_away_by_a_quiet_one(self):
        mixed = [
            result({"reliability.go.nil-deref": 0}, name="cobra"),
            result({"reliability.go.nil-deref": 30}, name="gin"),
        ]
        over = profile_noise.breaches(mixed, self.limits)
        self.assertEqual(len(over), 1)
        self.assertIn("gin", over[0])

    def test_every_breaching_rule_is_named_separately(self):
        found = result(
            {"reliability.go.err-shadow": 60, "reliability.go.nil-deref": 60}
        )
        self.assertEqual(len(profile_noise.breaches([found], self.limits)), 2)


class Tally(unittest.TestCase):
    REPORT = {
        "findings": [
            {"rule_id": "reliability.go.nil-deref"},
            {"rule_id": "reliability.go.nil-deref"},
            {"rule_id": "reliability.go.err-shadow"},
        ],
        "baselined": [{"rule_id": "reliability.go.nil-deref"}],
        "suppressed": [{"rule_id": "reliability.go.err-shadow"}],
        "metrics": {
            "files": {"a.go": {}, "b.go": {}},
            "totals": {"lines": 120, "code_lines": 100},
        },
    }

    def test_findings_are_counted_per_rule(self):
        _, _, findings = profile_noise.tally(self.REPORT)
        self.assertEqual(findings["reliability.go.nil-deref"], 3)
        self.assertEqual(findings["reliability.go.err-shadow"], 2)

    def test_files_and_code_lines_come_from_the_metrics_block(self):
        files, code_lines, _ = profile_noise.tally(self.REPORT)
        self.assertEqual(files, 2)
        self.assertEqual(code_lines, 100)

    def test_an_empty_report_tallies_to_nothing(self):
        self.assertEqual(profile_noise.tally({}), (0, 0, {}))


class Tables(unittest.TestCase):
    def setUp(self):
        self.limits = profile_noise.parse_limits(LIMITS)
        self.head = ["# generated=2026-09-03T00:00:00Z", "# binary_sha256=" + "0" * 64]

    def test_a_repository_file_carries_its_pin_in_the_header(self):
        text = profile_noise.repository_file(
            result({"reliability.go.err-shadow": 4}), self.limits, self.head
        )
        self.assertIn("# binary_sha256=" + "0" * 64, text)
        self.assertIn(f"# commit={SHA_B}", text)
        self.assertIn("# files_scanned=36", text)
        self.assertIn("# elapsed_seconds=1.25", text)
        self.assertIn("reliability.go.err-shadow\t4\t0.4000\t0.5000\twithin", text)

    def test_a_repository_file_marks_a_breach(self):
        text = profile_noise.repository_file(
            result({"reliability.go.err-shadow": 6}), self.limits, self.head
        )
        self.assertIn("reliability.go.err-shadow\t6\t0.6000\t0.5000\tbreach", text)

    def test_the_summary_gives_a_quiet_repository_a_row(self):
        text = profile_noise.summary_table(
            [result({}, name="cobra")], self.limits, self.head
        )
        rows = [line for line in text.splitlines() if not line.startswith("#")]
        self.assertEqual(len(rows), 2)
        self.assertTrue(rows[1].endswith("\t-\t0\t0.0000\t0.0000\twithin"))

    def test_the_summary_names_every_repository_and_rule(self):
        text = profile_noise.summary_table(
            [
                result({"reliability.go.err-shadow": 1}, name="cobra"),
                result({"reliability.go.nil-deref": 2}, name="gin"),
            ],
            self.limits,
            self.head,
        )
        rows = [line for line in text.splitlines() if not line.startswith("#")]
        self.assertEqual(len(rows), 3)
        self.assertIn("cobra", rows[1])
        self.assertIn("gin", rows[2])


class Arguments(unittest.TestCase):
    def test_the_defaults_point_at_the_committed_inputs(self):
        args = profile_noise.parse_args(["--binary", "b", "--out", "o"])
        self.assertEqual(args.profiles, "auto")
        self.assertEqual(args.noise_set, profile_noise.DEFAULT_NOISE_SET)
        self.assertEqual(args.limits, profile_noise.DEFAULT_LIMITS)

    def test_a_missing_binary_is_a_usage_failure_not_a_traceback(self):
        self.assertEqual(
            profile_noise.main(["--binary", "/nonexistent/siloscan", "--out", "/tmp"]),
            2,
        )


if __name__ == "__main__":
    unittest.main()
