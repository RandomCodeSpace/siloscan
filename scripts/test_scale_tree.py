#!/usr/bin/env python3
"""Deterministic tests for the scale-tree generator.

The generator is driven with synthetic source bytes so these tests need no Git
history and no pinned blob; the frozen recipe digest is checked by the command
itself every time it writes a tree.
"""

from __future__ import annotations

import filecmp
import hashlib
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import scale_tree  # noqa: E402

SOURCE = b"// sample source\nfn main() {}\n"
CONFIG = b"[duplication]\nmin_lines = 100000\n"


class Layout(unittest.TestCase):
    def test_the_recipe_shards_four_thousand_and_ninety_six_samples(self):
        paths = scale_tree.sample_paths()
        self.assertEqual(len(paths), 4096)
        self.assertEqual(paths[0], "src/00/sample_0000.rs")
        self.assertEqual(paths[99], "src/00/sample_0099.rs")
        self.assertEqual(paths[100], "src/01/sample_0100.rs")
        self.assertEqual(paths[-1], "src/40/sample_4095.rs")

    def test_the_last_shard_holds_the_remaining_ninety_six(self):
        shards: dict[str, int] = {}
        for path in scale_tree.sample_paths():
            shards[path.split("/")[1]] = shards.get(path.split("/")[1], 0) + 1
        self.assertEqual(len(shards), 41)
        self.assertEqual(shards["40"], 96)
        self.assertEqual({count for shard, count in shards.items() if shard != "40"}, {100})


class Generation(unittest.TestCase):
    def test_a_generated_tree_holds_exactly_four_thousand_and_ninety_seven_files(self):
        with tempfile.TemporaryDirectory() as work:
            out = Path(work) / "scale"
            count, total, _ = scale_tree.generate(out, SOURCE, CONFIG)
            self.assertEqual(count, scale_tree.FILE_COUNT)
            self.assertEqual(count, 4097)
            self.assertEqual(total, 4096 * len(SOURCE) + len(CONFIG))
            self.assertEqual(len(scale_tree.read_tree(out)), 4097)
            self.assertTrue((out / scale_tree.CONFIG_NAME).is_file())

    def test_two_generations_are_byte_identical(self):
        with tempfile.TemporaryDirectory() as work:
            first = Path(work) / "one"
            second = Path(work) / "two"
            first_result = scale_tree.generate(first, SOURCE, CONFIG)
            second_result = scale_tree.generate(second, SOURCE, CONFIG)
            self.assertEqual(first_result, second_result)

            comparison = filecmp.dircmp(first, second)
            self.assertEqual(self.differences(comparison), [])

    def differences(self, comparison: filecmp.dircmp) -> list[str]:
        found = list(comparison.left_only) + list(comparison.right_only) + list(comparison.diff_files)
        for child in comparison.subdirs.values():
            found += self.differences(child)
        return found

    def test_reading_a_written_tree_reproduces_its_digest(self):
        with tempfile.TemporaryDirectory() as work:
            out = Path(work) / "scale"
            _, _, digest = scale_tree.generate(out, SOURCE, CONFIG)
            self.assertEqual(scale_tree.manifest_digest(scale_tree.read_tree(out)), digest)

    def test_the_digest_follows_content_not_only_the_layout(self):
        with tempfile.TemporaryDirectory() as work:
            first = scale_tree.generate(Path(work) / "one", SOURCE, CONFIG)[2]
            second = scale_tree.generate(Path(work) / "two", SOURCE + b"\n", CONFIG)[2]
            self.assertNotEqual(first, second)


class Manifest(unittest.TestCase):
    def test_the_manifest_is_sha256sum_output_over_sorted_dot_slash_paths(self):
        entries = [("b.txt", b"two"), ("a.txt", b"one")]
        body = "".join(
            f"{hashlib.sha256(content).hexdigest()}  ./{path}\n"
            for path, content in sorted(entries)
        )
        self.assertEqual(
            scale_tree.manifest_digest(entries), hashlib.sha256(body.encode()).hexdigest()
        )

    def test_the_frozen_recipe_constants_are_the_recorded_ones(self):
        self.assertEqual(
            scale_tree.SOURCE_COMMIT, "880d211a463e97eb3c188f957e5592d88f36dcf8"
        )
        self.assertEqual(
            scale_tree.MANIFEST_SHA256,
            "32e15ce82ca06db7643fc3162454782f593bcf7c8822aa7f46b744930b3b5fb4",
        )


if __name__ == "__main__":
    unittest.main()
