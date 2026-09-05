#!/usr/bin/env python3
"""Tests for the gitleaks translation, centred on the path-regex to glob step.

The translator turns a regex into a glob, so the one failure that matters is a
glob that means something other than the regex did. Every path constraint
gitleaks v8.30.1 ships is pinned here with the globs it must produce and the
widening it must record; anything the translator does not understand has to
come back as None, which the converter turns into a logged skip rather than a
guess.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import convert_gitleaks  # noqa: E402


class PathGlobs(unittest.TestCase):
    """The five path constraints in gitleaks v8.30.1, as they are written."""

    def test_a_single_extension_becomes_one_suffix_glob(self):
        globs, folded, widenings = convert_gitleaks.path_globs(r"(?i)\.php$")
        self.assertEqual(globs, ["**/*.php"])
        self.assertTrue(folded)
        self.assertEqual(widenings, [])

    def test_an_alternation_becomes_one_glob_per_alternative(self):
        globs, folded, _ = convert_gitleaks.path_globs(r"(?i)\.(?:tf|hcl)$")
        self.assertEqual(globs, ["**/*.hcl", "**/*.tf"])
        self.assertTrue(folded)

    def test_an_optional_character_becomes_both_spellings(self):
        globs, _, _ = convert_gitleaks.path_globs(r"(?i)\.ya?ml$")
        self.assertEqual(globs, ["**/*.yaml", "**/*.yml"])

    def test_a_file_name_suffix_stays_unanchored(self):
        # The regex is unanchored, so it matches `my-nuget.config` too; the
        # glob has to keep doing that rather than pinning the whole name.
        globs, _, widenings = convert_gitleaks.path_globs(r"(?i)nuget\.config$")
        self.assertEqual(globs, ["**/*nuget.config"])
        self.assertEqual(widenings, [])

    def test_a_basename_anchor_is_dropped_and_the_widening_recorded(self):
        globs, folded, widenings = convert_gitleaks.path_globs(
            r"(?i)(?:^|\/)[^\/]+\.p(?:12|fx)$"
        )
        self.assertEqual(globs, ["**/*.p12", "**/*.pfx"])
        self.assertTrue(folded)
        self.assertEqual(widenings, [convert_gitleaks.BASENAME_ANCHOR_WIDENING])

    def test_case_folding_is_only_claimed_when_the_regex_asks(self):
        _, folded, _ = convert_gitleaks.path_globs(r"\.php$")
        self.assertFalse(folded)

    def test_a_regex_the_translator_cannot_express_is_refused(self):
        for pattern in [
            r"(?i)^src/.*\.go$",  # `.*` is not a literal
            r"(?i)\.php",  # not a suffix test
            r"(?i)\.[ch]$",  # a character class, not an alternation
            r"(?i)(\.tf|\.hcl)$",  # a capturing group
        ]:
            self.assertIsNone(convert_gitleaks.path_globs(pattern), pattern)


class Rules(unittest.TestCase):
    def test_a_path_only_rule_becomes_a_presence_rule(self):
        rule = convert_gitleaks.convert_rule(
            {
                "id": "pkcs12-file",
                "description": "Found a PKCS #12 file.",
                "path": r"(?i)(?:^|\/)[^\/]+\.p(?:12|fx)$",
            }
        )
        self.assertNotIn("secret", rule)
        self.assertEqual(rule["paths"]["include"], ["**/*.p12", "**/*.pfx"])
        self.assertTrue(rule["paths"]["case_insensitive"])
        self.assertTrue(any("widened" in c for c in rule["comments"]))

    def test_a_rule_with_neither_regex_nor_path_is_skipped(self):
        self.assertIsNone(
            convert_gitleaks.convert_rule({"id": "empty", "description": "d"})
        )

    def test_a_wide_repetition_is_narrowed_to_the_ascii_word_class(self):
        rule = convert_gitleaks.convert_rule(
            {
                "id": "pypi-upload-token",
                "description": "d",
                "regex": r"pypi-AgEIcHlwaS5vcmc[\w-]{50,1000}",
            }
        )
        self.assertEqual(
            rule["secret"]["pattern"], r"pypi-AgEIcHlwaS5vcmc[0-9A-Za-z_-]{50,1000}"
        )
        self.assertTrue(any("narrowed on import" in c for c in rule["comments"]))

    def test_the_only_deliberate_skip_is_the_generic_matcher(self):
        self.assertEqual(list(convert_gitleaks.MANUAL_SKIPS), ["generic-api-key"])
        self.assertIsNone(
            convert_gitleaks.convert_rule(
                {"id": "generic-api-key", "description": "d", "regex": "x"}
            )
        )

    def test_a_path_constrained_rule_keeps_its_content_pattern(self):
        rule = convert_gitleaks.convert_rule(
            {
                "id": "hashicorp-tf-password",
                "description": "d",
                "regex": r"password\s*=\s*\"([a-z0-9]{8,20})\"",
                "path": r"(?i)\.(?:tf|hcl)$",
            }
        )
        self.assertEqual(rule["paths"]["include"], ["**/*.hcl", "**/*.tf"])
        self.assertIn("password", rule["secret"]["pattern"])


class Emit(unittest.TestCase):
    def test_a_presence_rule_is_written_with_paths_and_no_payload(self):
        rule = convert_gitleaks.convert_rule(
            {
                "id": "pkcs12-file",
                "description": "Found a PKCS #12 file.",
                "path": r"(?i)(?:^|\/)[^\/]+\.p(?:12|fx)$",
            }
        )
        document = convert_gitleaks.emit([rule], "v8.30.1")
        self.assertIn("    paths:\n      case_insensitive: true\n", document)
        self.assertIn("        - '**/*.p12'\n", document)
        self.assertNotIn("    secret:", document)
        # Every comment sits above the rule it belongs to, indented as a
        # sequence comment so the document still parses.
        self.assertIn("\n  # gitleaks path constraint:", document)


if __name__ == "__main__":
    unittest.main()
