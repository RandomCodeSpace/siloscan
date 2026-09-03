#!/usr/bin/env bash
# THROWAWAY SPIKE for issue #78: what does turning parsing on for every source
# file cost on the frozen scale tree?
#
# Three arms over the same 4,097-file tree, same binary, same sink:
#   A  the shipped default pack alone            (no ast rule -> nothing parsed)
#   B  default pack + ten firing ast rules       (parse + query + findings)
#   C  default pack + the same ten shapes, silent(parse + query, no findings)
#
# One untimed warm-up per arm, then N paired samples in ABBA order per the
# acceptance plan's own measurement rule. Medians and ratios are computed by
# spike-medians.py.
#
# usage: spike-measure.sh <scale-tree> <binary> <out.tsv> [samples]
set -euo pipefail

TREE=$1
BIN=$2
OUT=$3
SAMPLES=${4:-9}
HERE=$(cd "$(dirname "$0")" && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

run() { # arm cache_state extra-args...
  local arm=$1 state=$2; shift 2
  local cache_args=()
  case $state in
    no-cache) cache_args=(--no-cache) ;;
    cold)     rm -rf "$WORK/cache-$arm"; cache_args=(--cache-dir "$WORK/cache-$arm") ;;
    warm)     cache_args=(--cache-dir "$WORK/cache-$arm") ;;
  esac
  /usr/bin/time -f '%e\t%M' -o "$WORK/time" \
    "$BIN" "$TREE" "${cache_args[@]}" "$@" --format json >/dev/null 2>"$WORK/err" || true
  cat "$WORK/time"
}

sample() { # arm state
  local arm=$1 state=$2
  local extra=()
  case $arm in
    B) extra=(--rules "$HERE/spike-pack") ;;
    C) extra=(--rules "$HERE/spike-pack-silent") ;;
  esac
  run "$arm" "$state" "${extra[@]+"${extra[@]}"}"
}

{
  echo "# tree=$TREE"
  echo "# binary=$BIN"
  echo "# binary_sha256=$(sha256sum "$BIN" | cut -d' ' -f1)"
  echo "# host=$(uname -sr); $(nproc) cpu"
  echo "# samples=$SAMPLES paired, ABBA order, one untimed warm-up per arm"
  printf 'arm\tcache_state\tsample\telapsed_seconds\tpeak_rss_kib\n'
} >"$OUT"

for state in no-cache warm; do
  # untimed warm-up per arm; for the warm lane this is also what seeds the cache
  for arm in A B C; do sample "$arm" "$state" >/dev/null; done
  for i in $(seq 1 "$SAMPLES"); do
    if [ $((i % 2)) -eq 1 ]; then order="A B C"; else order="C B A"; fi
    for arm in $order; do
      printf '%s\t%s\t%s\t%s\n' "$arm" "$state" "$i" "$(sample "$arm" "$state")" >>"$OUT"
    done
  done
done

echo "wrote $OUT"
