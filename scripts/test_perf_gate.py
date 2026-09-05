#!/usr/bin/env python3
"""Deterministic tests for the paired performance gate.

Every sample array here is synthetic. No binary is built, no scan is run, and
nothing touches a cache or state root: this file only exercises the statistics,
the per-cell verdicts, the twice-rule that ``--compare`` applies, the lane
argument table, and the two references the lanes are measured against with the
per-lane budgets that come with them.

The numbers in ``PerLaneVerdicts`` are the ones issue #89 measured, so the
budget is asserted against what it was declared for rather than against a round
number invented here.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import perf_gate  # noqa: E402

ROOTS = perf_gate.Roots(
    tree=Path("/w/tree"),
    rules=Path("/w/rules"),
    cache=Path("/w/cache"),
    state=Path("/w/state"),
    home=Path("/w/home"),
)


def raw(lanes: dict[str, dict[str, list[float]]]) -> dict:
    """A raw-sample document from {lane: {role: [(seconds, rss), ...]}}."""
    document = {"schema": 1, "samples": 0, "lanes": {}}
    for lane, roles in lanes.items():
        document["lanes"][lane] = {
            role: [
                {"sample": index, "seconds": seconds, "peak_rss_kib": rss}
                for index, (seconds, rss) in enumerate(samples, start=1)
            ]
            for role, samples in roles.items()
        }
    return document


def flat(seconds: float, rss: float, count: int = 9) -> list[tuple[float, float]]:
    return [(seconds, rss)] * count


class Statistics(unittest.TestCase):
    def test_median_of_an_odd_run_is_the_middle_value(self):
        self.assertEqual(perf_gate.median([3.0, 1.0, 2.0]), 2.0)

    def test_median_of_an_even_run_is_the_midpoint(self):
        self.assertEqual(perf_gate.median([1.0, 2.0, 3.0, 4.0]), 2.5)

    def test_a_flat_run_has_no_deviation(self):
        self.assertEqual(perf_gate.mad_fraction([4.0] * 9), 0.0)

    def test_mad_is_reported_as_a_fraction_of_the_median(self):
        # median 10, absolute deviations 2,1,0,1,2, median deviation 1.
        self.assertAlmostEqual(perf_gate.mad_fraction([8.0, 9.0, 10.0, 11.0, 12.0]), 0.1)

    def test_mad_ignores_a_single_far_outlier(self):
        self.assertAlmostEqual(perf_gate.mad_fraction([10.0, 10.0, 10.0, 10.0, 100.0]), 0.0)

    def test_a_zero_median_reports_no_deviation_rather_than_dividing(self):
        self.assertEqual(perf_gate.mad_fraction([0.0, 0.0, 0.0]), 0.0)

    def test_ratio_is_candidate_over_reference(self):
        self.assertAlmostEqual(perf_gate.ratio(2.1, 2.0), 1.05)

    def test_a_zero_reference_with_a_nonzero_candidate_is_infinite(self):
        self.assertEqual(perf_gate.ratio(1.0, 0.0), float("inf"))

    def test_two_zero_medians_are_equal(self):
        self.assertEqual(perf_gate.ratio(0.0, 0.0), 1.0)


class Verdicts(unittest.TestCase):
    """The decision is the same shape at every limit; the limit is the argument."""

    def test_a_faster_candidate_passes(self):
        self.assertEqual(perf_gate.verdict(0.80, 0.01, None, 1.05), "pass")

    def test_the_ratio_limit_itself_passes(self):
        self.assertEqual(perf_gate.verdict(1.05, 0.01, None, 1.05), "pass")

    def test_a_first_run_above_the_limit_is_only_suspected(self):
        self.assertEqual(perf_gate.verdict(1.06, 0.01, None, 1.05), "suspected")

    def test_a_rerun_above_the_limit_after_a_clean_first_run_stays_suspected(self):
        self.assertEqual(perf_gate.verdict(1.30, 0.01, 1.00, 1.05), "suspected")

    def test_above_the_limit_in_both_runs_rejects(self):
        self.assertEqual(perf_gate.verdict(1.06, 0.01, 1.06, 1.05), "reject")

    def test_a_noisy_reference_invalidates_before_any_ratio_is_believed(self):
        self.assertEqual(perf_gate.verdict(1.50, 0.21, 1.50, 1.05), "invalid")

    def test_the_mad_limit_itself_is_still_valid(self):
        self.assertEqual(perf_gate.verdict(1.00, 0.20, None, 1.05), "pass")

    def test_a_ratio_that_rejects_an_explicit_lane_passes_a_cold_bare_one(self):
        # 2.4x is the measured cost of the flip on the cold lane. It is a
        # rejection against v1.5.1 and inside the budget against v2.0.0.
        self.assertEqual(perf_gate.verdict(2.40, 0.01, 2.40, 1.05), "reject")
        self.assertEqual(perf_gate.verdict(2.40, 0.01, 2.40, 3.00), "pass")

    def test_the_twice_rule_reads_the_prior_run_against_the_same_limit(self):
        # Below the bare wall budget in both runs, so nothing to reject.
        self.assertEqual(perf_gate.verdict(1.20, 0.01, 1.20, 1.25), "pass")
        self.assertEqual(perf_gate.verdict(1.30, 0.01, 1.20, 1.25), "suspected")
        self.assertEqual(perf_gate.verdict(1.30, 0.01, 1.30, 1.25), "reject")


class Analysis(unittest.TestCase):
    def test_seven_lanes_produce_fourteen_cells(self):
        document = raw(
            {
                lane.name: {"reference": flat(1.0, 100.0), "candidate": flat(1.0, 100.0)}
                for lane in perf_gate.LANES
            }
        )
        cells = perf_gate.analyze(document)
        self.assertEqual(len(cells), 14)
        self.assertEqual(len({(cell.lane, cell.metric) for cell in cells}), 14)
        self.assertEqual(perf_gate.overall(cells), "pass")
        self.assertEqual(perf_gate.exit_code(cells), perf_gate.EXIT_PASS)

    def test_a_slower_cell_is_reported_per_metric(self):
        document = raw(
            {"explicit_no_cache": {"reference": flat(2.0, 100.0), "candidate": flat(2.4, 100.0)}}
        )
        time_cell, rss_cell = perf_gate.analyze(document)
        self.assertEqual(time_cell.metric, "seconds")
        self.assertAlmostEqual(time_cell.ratio, 1.2)
        self.assertEqual(time_cell.verdict, "suspected")
        self.assertEqual(rss_cell.metric, "peak_rss_kib")
        self.assertEqual(rss_cell.verdict, "pass")

    def test_a_faster_cell_never_offsets_a_larger_one(self):
        document = raw(
            {"explicit_no_cache": {"reference": flat(2.0, 100.0), "candidate": flat(0.5, 130.0)}}
        )
        cells = perf_gate.analyze(document)
        self.assertEqual([cell.verdict for cell in cells], ["pass", "suspected"])
        self.assertEqual(perf_gate.overall(cells), "suspected")
        self.assertEqual(perf_gate.exit_code(cells), perf_gate.EXIT_RERUN)

    def test_a_noisy_reference_invalidates_the_job(self):
        # median 3, median absolute deviation 1, so the reference spread is 33%.
        noisy = [(1.0, 100.0), (2.0, 100.0), (3.0, 100.0), (4.0, 100.0), (5.0, 100.0)]
        document = raw({"explicit_no_cache": {"reference": noisy, "candidate": flat(3.0, 100.0)}})
        cells = perf_gate.analyze(document)
        self.assertEqual(cells[0].verdict, "invalid")
        self.assertEqual(perf_gate.exit_code(cells), perf_gate.EXIT_RERUN)

    def test_reject_outranks_every_other_verdict(self):
        self.assertEqual(
            perf_gate.overall(
                [
                    perf_gate.Cell("a", "seconds", 1, 1, 1.0, 1.05, 0.0, "pass"),
                    perf_gate.Cell("b", "seconds", 1, 2, 2.0, 1.05, 0.0, "suspected"),
                    perf_gate.Cell("c", "seconds", 1, 2, 2.0, 1.05, 0.0, "reject"),
                ]
            ),
            "reject",
        )

    def test_the_table_names_every_cell_and_the_overall_verdict(self):
        document = raw(
            {
                lane.name: {"reference": flat(1.0, 100.0), "candidate": flat(1.0, 100.0)}
                for lane in perf_gate.LANES
            }
        )
        table = perf_gate.format_table(perf_gate.analyze(document))
        for lane in perf_gate.LANES:
            self.assertIn(lane.name, table)
        self.assertIn("wall time", table)
        self.assertIn("peak RSS", table)
        self.assertIn("overall: pass", table)


class TwiceRule(unittest.TestCase):
    def prior_and_current(self, prior_seconds: float, current_seconds: float) -> list[perf_gate.Cell]:
        prior = raw(
            {
                "explicit_no_cache": {
                    "reference": flat(2.0, 100.0),
                    "candidate": flat(prior_seconds, 100.0),
                }
            }
        )
        current = raw(
            {
                "explicit_no_cache": {
                    "reference": flat(2.0, 100.0),
                    "candidate": flat(current_seconds, 100.0),
                }
            }
        )
        return perf_gate.analyze(current, prior)

    def test_the_same_cell_above_the_limit_twice_rejects(self):
        cells = self.prior_and_current(2.4, 2.4)
        self.assertEqual(cells[0].verdict, "reject")
        self.assertEqual(perf_gate.exit_code(cells), perf_gate.EXIT_REJECT)

    def test_a_clean_rerun_after_a_suspected_first_run_passes(self):
        cells = self.prior_and_current(2.4, 2.0)
        self.assertEqual(cells[0].verdict, "pass")
        self.assertEqual(perf_gate.exit_code(cells), perf_gate.EXIT_PASS)

    def test_a_different_cell_above_the_limit_does_not_reject(self):
        prior = raw(
            {
                "explicit_no_cache": {
                    "reference": flat(2.0, 100.0),
                    "candidate": flat(2.0, 130.0),  # peak RSS was the suspected cell
                }
            }
        )
        current = raw(
            {
                "explicit_no_cache": {
                    "reference": flat(2.0, 100.0),
                    "candidate": flat(2.4, 100.0),  # wall time is, this time
                }
            }
        )
        time_cell, rss_cell = perf_gate.analyze(current, prior)
        self.assertEqual(time_cell.verdict, "suspected")
        self.assertEqual(rss_cell.verdict, "pass")

    def test_comparing_against_a_prior_run_of_a_different_lane_is_ignored(self):
        prior = raw(
            {"explicit_warm_cache": {"reference": flat(2.0, 100.0), "candidate": flat(9.0, 100.0)}}
        )
        current = raw(
            {"explicit_no_cache": {"reference": flat(2.0, 100.0), "candidate": flat(2.4, 100.0)}}
        )
        self.assertEqual(perf_gate.analyze(current, prior)[0].verdict, "suspected")


class LaneTable(unittest.TestCase):
    def test_the_plan_defines_exactly_these_seven_lanes(self):
        self.assertEqual(
            [lane.name for lane in perf_gate.LANES],
            [
                "explicit_no_cache",
                "explicit_cold_cache",
                "explicit_warm_cache",
                "bare_no_save_cold",
                "bare_no_save_warm",
                "bare_auto_save_first",
                "bare_auto_save_warm",
            ],
        )

    def test_an_explicit_lane_sends_both_binaries_the_same_v1_command(self):
        lane = perf_gate.LANES_BY_NAME["explicit_no_cache"]
        reference = perf_gate.lane_invocation(lane, "reference", Path("/bin/ref"), ROOTS)
        candidate = perf_gate.lane_invocation(lane, "candidate", Path("/bin/cand"), ROOTS)
        self.assertEqual(
            reference.argv,
            (
                "/bin/ref",
                "/w/tree",
                "--rules",
                "/w/rules",
                "--no-default-rules",
                "--no-cache",
                "--format",
                "json",
            ),
        )
        self.assertEqual(reference.argv[1:], candidate.argv[1:])
        self.assertEqual(reference.cwd, ROOTS.home)

    def test_a_cached_explicit_lane_passes_its_cache_root_as_an_argument(self):
        for name in ("explicit_cold_cache", "explicit_warm_cache"):
            invocation = perf_gate.lane_invocation(
                perf_gate.LANES_BY_NAME[name], "reference", Path("/bin/ref"), ROOTS
            )
            self.assertIn("--cache-dir", invocation.argv)
            self.assertNotIn("--no-cache", invocation.argv)
            self.assertEqual(invocation.argv[invocation.argv.index("--cache-dir") + 1], "/w/cache")

    def test_every_bare_lane_runs_from_inside_the_tree_with_no_path(self):
        for lane in perf_gate.LANES:
            if lane.mode != "bare":
                continue
            invocation = perf_gate.lane_invocation(lane, "reference", Path("/bin/ref"), ROOTS)
            self.assertEqual(invocation.argv[0], "/bin/ref", lane.name)
            self.assertEqual(invocation.cwd, ROOTS.tree, lane.name)

    def test_only_the_no_save_lanes_add_a_save_control_and_both_sides_get_it(self):
        # The v2.0.0 reference has --no-save, so the lane is symmetric: a
        # candidate that skipped a publication the reference performed would be
        # measured against work it did not do.
        for role in perf_gate.ROLES:
            added = {}
            for lane in perf_gate.LANES:
                if lane.mode != "bare":
                    continue
                invocation = perf_gate.lane_invocation(lane, role, Path("/bin/x"), ROOTS)
                added[lane.name] = invocation.argv[1:]
            self.assertEqual(
                added,
                {
                    "bare_no_save_cold": ("--no-save",),
                    "bare_no_save_warm": ("--no-save",),
                    "bare_auto_save_first": (),
                    "bare_auto_save_warm": (),
                },
                role,
            )

    def test_a_bare_lane_never_supplies_a_v1_scan_option(self):
        # --cache-dir would make the scan explicit, so bare lanes select their
        # cache root through the environment instead.
        for lane in perf_gate.LANES:
            if lane.mode != "bare":
                continue
            for role in perf_gate.ROLES:
                invocation = perf_gate.lane_invocation(lane, role, Path("/bin/x"), ROOTS)
                self.assertNotIn("--cache-dir", invocation.argv, lane.name)
                self.assertNotIn("--no-cache", invocation.argv, lane.name)
                self.assertNotIn("--format", invocation.argv, lane.name)

    def test_every_sample_pins_its_own_cache_state_and_home_roots(self):
        invocation = perf_gate.lane_invocation(
            perf_gate.LANES_BY_NAME["bare_auto_save_warm"], "candidate", Path("/bin/x"), ROOTS
        )
        self.assertEqual(
            invocation.env,
            {"HOME": "/w/home", "XDG_CACHE_HOME": "/w/cache", "XDG_STATE_HOME": "/w/state"},
        )

    def test_an_unknown_role_is_rejected(self):
        with self.assertRaises(ValueError):
            perf_gate.lane_invocation(perf_gate.LANES[0], "control", Path("/bin/x"), ROOTS)


class References(unittest.TestCase):
    """Which reference each lane is measured against, and at what budget."""

    def test_the_explicit_lanes_keep_the_v1_5_1_reference(self):
        for name in ("explicit_no_cache", "explicit_cold_cache", "explicit_warm_cache"):
            self.assertEqual(perf_gate.LANES_BY_NAME[name].reference_role, "reference", name)

    def test_every_bare_lane_is_measured_against_the_v2_0_0_reference(self):
        for lane in perf_gate.LANES:
            if lane.mode == "bare":
                self.assertEqual(lane.reference_role, "bare_reference", lane.name)

    def test_the_reference_role_is_one_of_the_two_binaries_the_gate_is_handed(self):
        for lane in perf_gate.LANES:
            self.assertIn(lane.reference_role, perf_gate.REFERENCE_ROLES, lane.name)

    def test_the_declared_budget_of_every_lane_and_metric(self):
        self.assertEqual(
            {
                lane.name: {metric: lane.ratio_limit(metric) for metric in perf_gate.METRICS}
                for lane in perf_gate.LANES
            },
            {
                "explicit_no_cache": {"seconds": 1.05, "peak_rss_kib": 1.05},
                "explicit_cold_cache": {"seconds": 1.05, "peak_rss_kib": 1.05},
                "explicit_warm_cache": {"seconds": 1.05, "peak_rss_kib": 1.05},
                "bare_no_save_cold": {"seconds": 3.00, "peak_rss_kib": 1.10},
                "bare_no_save_warm": {"seconds": 1.25, "peak_rss_kib": 1.10},
                "bare_auto_save_first": {"seconds": 1.25, "peak_rss_kib": 1.10},
                "bare_auto_save_warm": {"seconds": 1.25, "peak_rss_kib": 1.10},
            },
        )

    def test_a_lane_that_never_reads_a_warm_cache_carries_the_cold_wall_budget(self):
        for lane in perf_gate.LANES:
            if lane.mode != "bare":
                continue
            expected = 1.25 if lane.cache == "warm" else 3.00
            self.assertEqual(lane.ratio_limit("seconds"), expected, lane.name)

    def test_an_unknown_metric_is_rejected(self):
        with self.assertRaises(ValueError):
            perf_gate.LANES[0].ratio_limit("watts")


class PerLaneVerdicts(unittest.TestCase):
    """The measured cost of the flip passes the bare lanes and would not pass
    an explicit one, which is the whole point of the re-base."""

    def cells(self, lane_name: str, reference, candidate) -> list[perf_gate.Cell]:
        return perf_gate.analyze(
            raw({lane_name: {"reference": flat(*reference), "candidate": flat(*candidate)}})
        )

    def test_the_cold_bare_lane_absorbs_the_measured_2_4x_wall_cost(self):
        time_cell, rss_cell = self.cells("bare_no_save_cold", (1.80, 200_000), (4.32, 205_000))
        self.assertAlmostEqual(time_cell.ratio, 2.4)
        self.assertEqual(time_cell.limit, 3.00)
        self.assertEqual(time_cell.verdict, "pass")
        self.assertEqual(rss_cell.limit, 1.10)
        self.assertEqual(rss_cell.verdict, "pass")

    def test_the_same_ratio_on_an_explicit_lane_is_still_suspected(self):
        time_cell, _ = self.cells("explicit_cold_cache", (1.80, 200_000), (4.32, 205_000))
        self.assertEqual(time_cell.limit, 1.05)
        self.assertEqual(time_cell.verdict, "suspected")

    def test_the_warm_bare_lane_holds_the_tighter_wall_budget(self):
        passing, _ = self.cells("bare_no_save_warm", (0.93, 156_000), (1.08, 158_000))
        self.assertEqual(passing.limit, 1.25)
        self.assertEqual(passing.verdict, "pass")
        failing, _ = self.cells("bare_no_save_warm", (0.93, 156_000), (1.30, 158_000))
        self.assertEqual(failing.verdict, "suspected")

    def test_the_cold_wall_budget_does_not_loosen_peak_rss(self):
        _, rss_cell = self.cells("bare_no_save_cold", (1.80, 200_000), (1.80, 240_000))
        self.assertAlmostEqual(rss_cell.ratio, 1.2)
        self.assertEqual(rss_cell.limit, 1.10)
        self.assertEqual(rss_cell.verdict, "suspected")

    def test_the_table_names_the_reference_and_the_limit_of_every_cell(self):
        document = raw(
            {
                lane.name: {"reference": flat(1.0, 100.0), "candidate": flat(1.0, 100.0)}
                for lane in perf_gate.LANES
            }
        )
        table = perf_gate.format_table(perf_gate.analyze(document))
        self.assertIn("v1.5.1", table)
        self.assertIn("v2.0.0", table)
        self.assertIn("3.00", table)
        self.assertIn("1.25", table)
        self.assertIn("1.10", table)


class SampleRoots(unittest.TestCase):
    def test_a_cold_lane_gets_a_new_cache_root_for_every_sample(self):
        lane = perf_gate.LANES_BY_NAME["explicit_cold_cache"]
        first = perf_gate.sample_roots(Path("/w"), lane, "candidate", "1", Path("/t"), Path("/r"))
        second = perf_gate.sample_roots(Path("/w"), lane, "candidate", "2", Path("/t"), Path("/r"))
        self.assertNotEqual(first.cache, second.cache)

    def test_a_warm_lane_reuses_one_cache_root_per_binary(self):
        lane = perf_gate.LANES_BY_NAME["explicit_warm_cache"]
        first = perf_gate.sample_roots(Path("/w"), lane, "candidate", "1", Path("/t"), Path("/r"))
        second = perf_gate.sample_roots(Path("/w"), lane, "candidate", "2", Path("/t"), Path("/r"))
        reference = perf_gate.sample_roots(Path("/w"), lane, "reference", "1", Path("/t"), Path("/r"))
        self.assertEqual(first.cache, second.cache)
        self.assertNotEqual(first.cache, reference.cache)

    def test_a_first_publication_lane_gets_a_new_state_root_for_every_sample(self):
        lane = perf_gate.LANES_BY_NAME["bare_auto_save_first"]
        first = perf_gate.sample_roots(Path("/w"), lane, "candidate", "1", Path("/t"), Path("/r"))
        second = perf_gate.sample_roots(Path("/w"), lane, "candidate", "2", Path("/t"), Path("/r"))
        self.assertNotEqual(first.state, second.state)
        self.assertEqual(first.cache, second.cache)

    def test_a_replacement_lane_reuses_the_state_root_the_warm_up_published_into(self):
        lane = perf_gate.LANES_BY_NAME["bare_auto_save_warm"]
        warmup = perf_gate.sample_roots(
            Path("/w"), lane, "candidate", "warmup", Path("/t"), Path("/r")
        )
        sample = perf_gate.sample_roots(Path("/w"), lane, "candidate", "1", Path("/t"), Path("/r"))
        self.assertEqual(warmup.state, sample.state)

    def test_no_state_root_is_ever_placed_inside_the_scanned_tree(self):
        tree = Path("/w/tree")
        for lane in perf_gate.LANES:
            roots = perf_gate.sample_roots(Path("/w/work"), lane, "candidate", "1", tree, Path("/r"))
            self.assertFalse(str(roots.state).startswith(str(tree) + "/"), lane.name)
            self.assertFalse(str(roots.cache).startswith(str(tree) + "/"), lane.name)


if __name__ == "__main__":
    unittest.main()
