#!/usr/bin/env bash
# Require every Go coverage block to have executed. Checking raw hit counts
# avoids accepting a rounded "100.0%" with uncovered statements remaining.
set -euo pipefail
COVERAGE_PROFILE="${1:?Usage: check-coverage.sh <go-coverage-profile>}"
awk '
NR == 1 {
  if ($0 !~ /^mode: (set|count|atomic)$/) invalid = 1
  next
}
NF != 3 || $2 !~ /^[0-9]+$/ || $3 !~ /^[0-9]+$/ { invalid = 1; next }
{
  total += $2
  if ($3 == 0) {
    uncovered += $2
    print "Uncovered: " $1 " (" $2 " statements)"
  }
}
END {
  if (invalid || total == 0) {
    print "Invalid or empty coverage profile"
    exit 1
  }
  if (uncovered > 0) {
    print uncovered " of " total " statements are uncovered"
    exit 1
  }
  print "100% statement coverage: all " total " statements executed"
}' "$COVERAGE_PROFILE"
