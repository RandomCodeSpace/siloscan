#!/usr/bin/env python3
"""THROWAWAY SPIKE for issue #78: medians and ratios from spike-timings.txt.

Per (arm, cache_state): median wall time, median peak RSS, and the ratio
against arm A of the same cache state. The acceptance plan's gate is 1.05.
"""

import statistics
import sys
from collections import defaultdict


def main(path: str) -> int:
    rows = defaultdict(lambda: ([], []))
    with open(path) as handle:
        for line in handle:
            if line.startswith("#") or line.startswith("arm\t"):
                continue
            arm, state, _sample, elapsed, rss = line.rstrip("\n").split("\t")
            rows[(state, arm)][0].append(float(elapsed))
            rows[(state, arm)][1].append(float(rss))

    print("cache_state\tarm\tn\tmedian_s\tratio_s\tmedian_rss_kib\tratio_rss")
    for state in ("no-cache", "warm"):
        base = rows.get((state, "A"))
        if base is None:
            continue
        base_s = statistics.median(base[0])
        base_r = statistics.median(base[1])
        for arm in ("A", "B", "C"):
            sample = rows.get((state, arm))
            if sample is None:
                continue
            med_s = statistics.median(sample[0])
            med_r = statistics.median(sample[1])
            print(
                f"{state}\t{arm}\t{len(sample[0])}\t{med_s:.3f}\t{med_s / base_s:.3f}"
                f"\t{med_r:.0f}\t{med_r / base_r:.3f}"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1]))
