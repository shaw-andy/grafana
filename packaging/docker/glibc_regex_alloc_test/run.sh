#!/bin/bash
# Fault-inject realloc inside regcomp and regexec.
#
# The alpine image stage in the repository Dockerfile extracts GNU C Library
# libc.so.6 (GLIBC_VERSION) so glibc-linked plugins can run. These cases
# compile or match ordinary patterns and fail one realloc at a time. A fixed
# library returns REG_ESPACE or success. The vulnerable library frees the
# same heap block twice and aborts.
#
# The script exits 0 when the Dockerfile no longer installs that libc, or
# when every injected failure survives. It exits 1 while a double-free abort
# is still reachable. It exits 2 when the harness itself cannot run.
set -u

root=$(cd "$(dirname "$0")/../../.." && pwd)
dockerfile="$root/Dockerfile"
here=$(cd "$(dirname "$0")" && pwd)

if [[ ! -f "$dockerfile" ]]; then
  echo "missing Dockerfile at $dockerfile" >&2
  exit 2
fi

# Uncommented extract of the compat libc into the image.
ships_glibc=0
while IFS= read -r line; do
  [[ "$line" =~ ^[[:space:]]*# ]] && continue
  if [[ "$line" == *"usr/glibc-compat/lib/libc.so.6"* ]]; then
    ships_glibc=1
    break
  fi
done < "$dockerfile"

if [[ "$ships_glibc" -eq 0 ]]; then
  echo "PASS: Dockerfile does not install glibc libc.so.6"
  exit 0
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

gcc -shared -fPIC -o "$work/failrealloc.so" "$here/failrealloc.c" -ldl
gcc -o "$work/exercise" "$here/exercise.c" -ldl

run_one() {
  local mode=$1 fail=$2 pattern=$3 subject=$4
  LD_PRELOAD="$work/failrealloc.so" "$work/exercise" "$mode" "$fail" "$pattern" "$subject"
}

# Six copies of every non-overlapping ASCII pair, so build_range_exp
# has to grow both range arrays with realloc.
range='['
for _ in 1 2 3 4 5 6; do
  range+='a-bc-de-fg-hi-jk-lm-no-pq-rs-tu-vw-xy-z'
done
range+=']'

# name, mode, pattern, subject
cases=(
  $'dfa\tcomp\t\\<a\\>\\<b\\>\\<c\\>\\<d\\>\\<e\\>\t'
  "$(printf 'range\tcomp\t%s\t' "$range")"
  $'backref\texec\t(a+)\\1\taaaaaaaaaaaaaaaaaaaa'
)

fail=0
for spec in "${cases[@]}"; do
  IFS=$'\t' read -r name mode pattern subject <<<"$spec"
  baseline=$(run_one "$mode" 0 "$pattern" "$subject" 2>"$work/base.err") || {
    echo "FAIL: $name baseline could not run" >&2
    cat "$work/base.err" >&2
    exit 2
  }
  if [[ "$mode" == comp && "$baseline" != *regcomp=0* ]]; then
    echo "FAIL: $name baseline did not compile: $baseline" >&2
    exit 2
  fi
  if [[ "$mode" == exec && "$baseline" != *regexec=0* ]]; then
    echo "FAIL: $name baseline did not match: $baseline" >&2
    exit 2
  fi
  count=$(sed -n 's/^armed_reallocs=//p' "$work/base.err" | tail -1)
  if [[ -z "${count}" || "$count" -lt 1 ]]; then
    echo "FAIL: $name did not report reallocs" >&2
    exit 2
  fi
  echo "$name: $count reallocs during a successful call"
  for ((i = 1; i <= count; i++)); do
    set +e
    out=$(run_one "$mode" "$i" "$pattern" "$subject" 2>"$work/err")
    rc=$?
    set -e
    if [[ "$rc" -eq 0 ]]; then
      continue
    fi
    echo "FAIL: $name realloc #$i aborted (exit $rc)"
    sed -n '1,20p' "$work/err"
    fail=1
    break
  done
done

if [[ "$fail" -ne 0 ]]; then
  echo "vulnerable: regcomp/regexec aborted after a failed realloc"
  exit 1
fi

echo "PASS: every injected realloc failure returned without aborting"
exit 0
