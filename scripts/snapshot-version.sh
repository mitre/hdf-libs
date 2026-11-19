# shellcheck shell=bash
#
# Shared snapshot version shape and ordering. Sourced, not executed.
#
# A snapshot version is <release>-next.<run-id>.<attempt>, and versions order by release,
# then run ID, then attempt — the order the publishing workflow issues them in. Comparison
# is base ten throughout: a run ID is a long decimal and must never be read as octal.

readonly VERSION_PATTERN='^([0-9]+)\.([0-9]+)\.([0-9]+)-next\.([0-9]+)\.([0-9]+)$'

# Succeeds when snapshot version $1 is strictly newer than $2.
version_newer() {
  local -a a b
  local i
  [[ "$1" =~ $VERSION_PATTERN ]] && a=("${BASH_REMATCH[@]:1}") || return 1
  [[ "$2" =~ $VERSION_PATTERN ]] && b=("${BASH_REMATCH[@]:1}") || return 1
  for i in 0 1 2 3 4; do
    ((10#${a[i]} > 10#${b[i]})) && return 0
    ((10#${a[i]} < 10#${b[i]})) && return 1
  done
  return 1
}
