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
import tempfile
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
        files_total=65,
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
        self.assertEqual(len(parsed), 33)
        self.assertEqual(len({r.commit for r in parsed}), 33)
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

    def test_a_secrets_rule_never_spends_a_profile_budget(self):
        # tally() already drops these; breaches() repeats the filter so a
        # result built any other way cannot charge one to a profile.
        found = result({"secrets.generic-api-key": 400})
        self.assertEqual(profile_noise.breaches([found], self.limits), [])

    def test_every_breaching_rule_is_named_separately(self):
        found = result(
            {"reliability.go.err-shadow": 60, "reliability.go.nil-deref": 60}
        )
        self.assertEqual(len(profile_noise.breaches([found], self.limits)), 2)


class Languages(unittest.TestCase):
    def test_the_extension_table_covers_the_ten_grammars(self):
        self.assertEqual(len(set(profile_noise.EXTENSIONS.values())), 10)

    def test_a_path_maps_by_its_extension(self):
        self.assertEqual(profile_noise.language_of("src/cmd/root.go"), "go")
        self.assertEqual(profile_noise.language_of("a/b.TSX"), "typescript")
        self.assertEqual(profile_noise.language_of("include/x.hpp"), "cpp")

    def test_an_unknown_extension_has_no_language(self):
        self.assertIsNone(profile_noise.language_of("README.md"))

    def test_an_extensionless_file_is_not_its_own_name(self):
        self.assertIsNone(profile_noise.language_of("Makefile"))
        self.assertIsNone(profile_noise.language_of("bin/go"))

    def test_a_dot_in_a_directory_is_not_an_extension(self):
        self.assertIsNone(profile_noise.language_of("vendor.d/LICENSE"))

    def test_a_header_with_no_tree_to_read_stays_c(self):
        self.assertEqual(profile_noise.language_of("include/widget.h"), "c")


#: The four headers `lang.rs`'s own unit tests use, so the two implementations
#: are held to the same fixtures.
C_HEADER = (
    "#ifndef WIDGET_H\n"
    "#define WIDGET_H\n"
    "struct widget { int id; };\n"
    "void widget_init(struct widget *w);\n"
    "#endif\n"
)
CPP_HEADER = "#pragma once\nclass Widget {\npublic:\n  int id() const;\n};\n"
C_HEADER_WITH_CPP_WORDS_IN_A_COMMENT = (
    "/*\n"
    " * namespace foo is not a thing here, and neither is\n"
    " * class bar or template <typename T>.\n"
    " */\n"
    "// namespace again\n"
    "int widget_id(void);\n"
)


class CppHeaders(unittest.TestCase):
    def test_a_c_header_is_not_cpp(self):
        self.assertFalse(profile_noise.is_cpp_header(C_HEADER))

    def test_a_header_with_a_class_is_cpp(self):
        self.assertTrue(profile_noise.is_cpp_header(CPP_HEADER))

    def test_a_comment_mentioning_namespace_does_not_make_a_header_cpp(self):
        self.assertFalse(
            profile_noise.is_cpp_header(C_HEADER_WITH_CPP_WORDS_IN_A_COMMENT)
        )

    def test_an_empty_header_is_not_cpp(self):
        self.assertFalse(profile_noise.is_cpp_header(""))

    def test_code_after_a_block_comment_is_read(self):
        self.assertTrue(
            profile_noise.is_cpp_header("/* a comment */ namespace widget {\n")
        )

    def test_a_header_in_a_tree_is_classified_by_its_content(self):
        with tempfile.TemporaryDirectory() as scratch:
            tree = Path(scratch)
            (tree / "include").mkdir()
            for name, content in (
                ("c.h", C_HEADER),
                ("cpp.h", CPP_HEADER),
                ("comment.h", C_HEADER_WITH_CPP_WORDS_IN_A_COMMENT),
                ("empty.h", ""),
            ):
                (tree / "include" / name).write_text(content, encoding="utf-8")
            language = {
                name: profile_noise.language_of(f"include/{name}", tree)
                for name in ("c.h", "cpp.h", "comment.h", "empty.h")
            }
        self.assertEqual(
            language,
            {"c.h": "c", "cpp.h": "cpp", "comment.h": "c", "empty.h": "c"},
        )

    def test_a_header_the_tree_does_not_have_falls_back_to_the_table(self):
        with tempfile.TemporaryDirectory() as scratch:
            self.assertEqual(
                profile_noise.language_of("include/gone.h", Path(scratch)), "c"
            )

    def test_a_cpp_header_counts_in_the_cpp_denominator(self):
        with tempfile.TemporaryDirectory() as scratch:
            tree = Path(scratch)
            (tree / "a.h").write_text(CPP_HEADER, encoding="utf-8")
            (tree / "b.h").write_text(C_HEADER, encoding="utf-8")
            report = {
                "metrics": {
                    "files": {
                        "a.h": {"code_lines": 40},
                        "b.h": {"code_lines": 60},
                    }
                },
                "findings": [],
            }
            files, files_total, code_lines, _ = profile_noise.tally(
                report, "cpp", tree
            )
        self.assertEqual((files, files_total, code_lines), (1, 2, 40))


class ProfileFamilies(unittest.TestCase):
    def test_the_two_profile_families_are_profile_rules(self):
        self.assertTrue(profile_noise.is_profile_rule("reliability.go.nil-deref"))
        self.assertTrue(profile_noise.is_profile_rule("maintainability.go.long-fn"))

    def test_a_secrets_rule_is_not_a_profile_rule(self):
        self.assertFalse(profile_noise.is_profile_rule("secrets.aws-access-key-id"))
        self.assertFalse(profile_noise.is_profile_rule("metrics.duplicate-block"))


class Tally(unittest.TestCase):
    REPORT = {
        "findings": [
            {"rule_id": "reliability.go.nil-deref"},
            {"rule_id": "reliability.go.nil-deref"},
            {"rule_id": "reliability.go.err-shadow"},
            {"rule_id": "secrets.generic-api-key"},
        ],
        "baselined": [{"rule_id": "reliability.go.nil-deref"}],
        "suppressed": [{"rule_id": "reliability.go.err-shadow"}],
        "metrics": {
            "files": {
                "a.go": {"lines": 60, "code_lines": 40},
                "b.go": {"lines": 90, "code_lines": 60},
                "vendor/tool.py": {"lines": 300, "code_lines": 250},
                "README.md": {"lines": 20},
            },
            "totals": {"lines": 470, "code_lines": 350},
        },
    }

    def test_findings_are_counted_per_rule(self):
        *_, findings = profile_noise.tally(self.REPORT, "go")
        self.assertEqual(findings["reliability.go.nil-deref"], 3)
        self.assertEqual(findings["reliability.go.err-shadow"], 2)

    def test_only_profile_rules_are_tallied(self):
        # --profiles adds to the secrets pack rather than replacing it, so
        # every real run carries secrets findings that are not a profile's to
        # answer for.
        *_, findings = profile_noise.tally(self.REPORT, "go")
        self.assertEqual(
            sorted(findings),
            ["reliability.go.err-shadow", "reliability.go.nil-deref"],
        )
        self.assertNotIn("secrets.generic-api-key", findings)

    def test_code_lines_are_the_measured_language_and_not_the_total(self):
        files, files_total, code_lines, _ = profile_noise.tally(self.REPORT, "go")
        self.assertEqual(files, 2)
        self.assertEqual(files_total, 4)
        # 40 + 60, not the 350 that totals.code_lines sums across languages.
        self.assertEqual(code_lines, 100)

    def test_a_file_with_no_code_lines_contributes_none(self):
        _, _, code_lines, _ = profile_noise.tally(
            {"metrics": {"files": {"a.go": {"lines": 10}}}}, "go"
        )
        self.assertEqual(code_lines, 0)

    def test_a_language_with_no_files_measures_nothing(self):
        files, files_total, code_lines, _ = profile_noise.tally(self.REPORT, "ruby")
        self.assertEqual((files, files_total, code_lines), (0, 4, 0))

    def test_an_empty_report_tallies_to_nothing(self):
        self.assertEqual(profile_noise.tally({}, "go"), (0, 0, 0, {}))


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
        self.assertIn("# files_total=65", text)
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


class ScanCommand(unittest.TestCase):
    def test_with_no_rules_the_command_is_the_one_this_script_always_ran(self):
        self.assertEqual(
            profile_noise.scan_command(Path("bin/siloscan"), Path("/t/tree"), "auto"),
            [
                "bin/siloscan",
                "/t/tree",
                "--profiles",
                "auto",
                "--no-cache",
                "--format",
                "json",
            ],
        )

    def test_every_rules_directory_is_passed_through_after_the_profiles(self):
        self.assertEqual(
            profile_noise.scan_command(
                Path("bin/siloscan"),
                Path("/t/tree"),
                "auto",
                [Path("/t/a"), Path("/t/b")],
            ),
            [
                "bin/siloscan",
                "/t/tree",
                "--profiles",
                "auto",
                "--rules",
                "/t/a",
                "--rules",
                "/t/b",
                "--no-cache",
                "--format",
                "json",
            ],
        )

    def test_the_header_records_the_rules_it_was_run_with(self):
        head = profile_noise.header(
            Path(__file__), "auto", Path("n.md"), Path("l.tsv"), [Path("/t/a")]
        )
        self.assertIn(
            "# command=siloscan REPO --profiles auto --rules /t/a "
            "--no-cache --format json",
            head,
        )


class Arguments(unittest.TestCase):
    def test_the_defaults_point_at_the_committed_inputs(self):
        args = profile_noise.parse_args(["--binary", "b", "--out", "o"])
        self.assertEqual(args.profiles, "auto")
        self.assertEqual(args.noise_set, profile_noise.DEFAULT_NOISE_SET)
        self.assertEqual(args.limits, profile_noise.DEFAULT_LIMITS)
        self.assertEqual(args.rules, [])

    def test_rules_is_repeatable(self):
        args = profile_noise.parse_args(
            ["--binary", "b", "--out", "o", "--rules", "a", "--rules", "b"]
        )
        self.assertEqual(args.rules, [Path("a"), Path("b")])

    def test_a_missing_binary_is_a_usage_failure_not_a_traceback(self):
        self.assertEqual(
            profile_noise.main(["--binary", "/nonexistent/siloscan", "--out", "/tmp"]),
            2,
        )


if __name__ == "__main__":
    unittest.main()
