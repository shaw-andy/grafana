#!/bin/bash
# Exercises scripts/build/sign_packages.sh and the RPM macros it installs.
#
# The signing passphrase must not be readable by another local user while
# rpm --addsign is running, must not be written into a file another user
# prepared, and must not remain after the script exits (including when rpm
# fails or the script is signaled). These checks fail until that is true.

set -u

root=$(cd "$(dirname "$0")/../.." && pwd)
script="$root/scripts/build/sign_packages.sh"

failures=0
work=$(mktemp -d)
chmod 700 "$work"

cleanup() {
  if [ -n "${leader:-}" ]; then
    kill -TERM -- "-$leader" >/dev/null 2>&1 || true
    wait "$leader" >/dev/null 2>&1 || true
  fi
  sudo -n rm -f /tmp/gpg-passphrase >/dev/null 2>&1 || rm -f /tmp/gpg-passphrase
  rm -rf "$work"
}
trap cleanup EXIT

passphrase=$(openssl rand -hex 32)
secret_file="$work/expected"
printf '%s\n' "$passphrase" >"$secret_file"
chmod 600 "$secret_file"

key_home="$work/keygen"
mkdir -p "$key_home"
chmod 700 "$key_home"
export GNUPGHOME="$key_home"
gpg --batch --pinentry-mode loopback --passphrase-fd 3 \
  --quick-gen-key "Grafana signing test" default default never \
  3<<<"$passphrase" >"$work/gpg-gen.out" 2>&1
exported_key="$work/private.key"
gpg --batch --pinentry-mode loopback --passphrase-fd 3 \
  --export-secret-keys --armor >"$exported_key" 3<<<"$passphrase"
chmod 600 "$exported_key"
unset GNUPGHOME

note() {
  printf '%s\n' "$*"
}

fail() {
  note "FAIL: $*"
  failures=$((failures + 1))
}

pass() {
  note "PASS: $*"
}

other_can_read() {
  sudo -n -u nobody test -r "$1"
}

file_is_passphrase() {
  cmp -s "$1" "$secret_file"
}

# Print mode and whether nobody can read a passphrase file. Never print contents.
report_exposure() {
  local label=$1
  local path=$2
  local mode other
  if [ ! -e "$path" ]; then
    note "$label: $path does not exist"
    return 1
  fi
  mode=$(stat -c %a "$path")
  other=$((10#$mode % 10))
  if file_is_passphrase "$path" && other_can_read "$path"; then
    fail "$label: another user read the signing passphrase at $path (mode $mode)"
    return 0
  fi
  if file_is_passphrase "$path" && [ "$other" -ge 4 ]; then
    fail "$label: $path holds the signing passphrase and is world-readable (mode $mode)"
    return 0
  fi
  note "$label: $path mode $mode is not readable by another user"
  return 1
}

scan_passphrase_files() {
  local label=$1
  local found=1
  local path mode
  # Shell redirection creates the file before rpm starts. Search every regular
  # file the operator owns, plus the path the installed macros name.
  while IFS= read -r path; do
    [ -f "$path" ] || continue
    mode=$(stat -c %s "$path")
    if [ "$mode" -gt 1024 ]; then
      continue
    fi
    if file_is_passphrase "$path"; then
      report_exposure "$label" "$path" && found=0
    fi
  done < <(find /tmp "$work" -user "$(id -u)" -type f 2>/dev/null || true)

  local macros="${HOME:-}/.rpmmacros"
  if [ -f "$macros" ]; then
    local macro_path
    macro_path=$(sed -n 's/.*--passphrase-file[[:space:]]\{1,\}\([^[:space:]]*\).*/\1/p' "$macros" | head -n 1)
    if [ -n "$macro_path" ] && [ -f "$macro_path" ] && file_is_passphrase "$macro_path"; then
      report_exposure "$label macro" "$macro_path" && found=0
    fi
  fi
  return $found
}

stop_signing() {
  if [ -n "${leader:-}" ]; then
    kill -TERM -- "-$leader" >/dev/null 2>&1 || true
    wait "$leader" >/dev/null 2>&1 || true
    leader=
  fi
  rm -f /tmp/gpg-passphrase
}

prepare_home() {
  local home=$1
  mkdir -p "$home/private-repo/signing" "$home/.gnupg"
  chmod 750 "$home"
  chmod 700 "$home/.gnupg"
  cp "$exported_key" "$home/private-repo/signing/private.key"
  chmod 600 "$home/private-repo/signing/private.key"
}

make_stall_rpm() {
  local bindir=$1
  mkdir -p "$bindir"
  cat >"$bindir/rpm" <<'EOF'
#!/bin/bash
printf '%s\n' "$$" >"${RPM_STALL_DIR}/rpm.pid"
: >"${RPM_STALL_DIR}/rpm.entered"
while [ ! -f "${RPM_STALL_DIR}/release" ]; do
  sleep 0.05
done
exit "${RPM_EXIT_CODE:-0}"
EOF
  chmod 755 "$bindir/rpm"
}

start_signing() {
  local home=$1
  local stall=$2
  local package=$3
  local rpm_exit=$4
  local bindir=$5
  : >"$package"
  make_stall_rpm "$bindir"
  rm -f "$stall/release" "$stall/rpm.entered"
  # setsid makes the signing script a session leader so a later signal
  # reaches it and the rpm it is waiting on.
  setsid env \
    HOME="$home" \
    GPG_KEY_PASSWORD="$passphrase" \
    PATH="$bindir:$PATH" \
    RPM_STALL_DIR="$stall" \
    RPM_EXIT_CODE="$rpm_exit" \
    bash "$script" "$package" >"$work/sign.out" 2>&1 &
  leader=$!
}

wait_until_rpm() {
  local stall=$1
  local i
  for i in $(seq 1 200); do
    if [ -f "$stall/rpm.entered" ]; then
      return 0
    fi
    if ! kill -0 "$leader" >/dev/null 2>&1; then
      return 1
    fi
    sleep 0.05
  done
  return 1
}

release_rpm() {
  local stall=$1
  : >"$stall/release"
  local status=0
  wait "$leader" || status=$?
  leader=
  return $status
}

assert_no_leftover() {
  local label=$1
  if [ -e /tmp/gpg-passphrase ]; then
    local mode
    mode=$(stat -c %a /tmp/gpg-passphrase)
    fail "$label: /tmp/gpg-passphrase still exists after the script exited (mode $mode)"
  else
    pass "$label: /tmp/gpg-passphrase is gone after the script exited"
  fi
  if scan_passphrase_files "$label leftover"; then
    fail "$label: signing passphrase is still in a file another user can read"
  fi
}

# --- controls: the script must not create the file if it rejects the invocation ---

rm -f /tmp/gpg-passphrase
if env -u GPG_KEY_PASSWORD bash "$script" "$work/missing-pass.rpm" >"$work/no-pass.out" 2>&1; then
  fail "script exited 0 without a signing passphrase"
else
  pass "script rejects a missing signing passphrase"
fi
if [ -e /tmp/gpg-passphrase ]; then
  fail "missing signing passphrase still created /tmp/gpg-passphrase"
else
  pass "missing signing passphrase does not create /tmp/gpg-passphrase"
fi

rm -f /tmp/gpg-passphrase
if env GPG_KEY_PASSWORD="$passphrase" bash "$script" >"$work/no-pkg.out" 2>&1; then
  fail "script exited 0 without a package path"
else
  pass "script rejects a missing package path"
fi
if [ -e /tmp/gpg-passphrase ]; then
  fail "missing package path still created /tmp/gpg-passphrase"
else
  pass "missing package path does not create /tmp/gpg-passphrase"
fi

# --- rpm fails after the passphrase file is created ---

home="$work/home-fail"
stall="$work/stall-fail"
prepare_home "$home"
mkdir -p "$stall"
start_signing "$home" "$stall" "$work/pkg-fail.rpm" 1 "$work/bin-fail"
if wait_until_rpm "$stall"; then
  pass "signing reached rpm --addsign with the passphrase set"
  HOME="$home"
  if scan_passphrase_files "while rpm --addsign runs"; then
    :
  else
    pass "another user could not read the signing passphrase while rpm --addsign runs"
  fi
  unset HOME
  status=0
  release_rpm "$stall" || status=$?
  if [ "$status" -eq 0 ]; then
    fail "script exited 0 when rpm --addsign failed"
  else
    pass "script returned non-zero when rpm --addsign failed (status $status)"
  fi
  HOME="$home"
  assert_no_leftover "after rpm failure"
  unset HOME
else
  fail "signing script exited before rpm --addsign"
  note "script output follows, with the passphrase redacted"
  sed "s/${passphrase}/[redacted]/g" "$work/sign.out" || true
  stop_signing
fi

# --- the script is signaled while rpm --addsign is in progress ---

home="$work/home-signal"
stall="$work/stall-signal"
prepare_home "$home"
mkdir -p "$stall"
start_signing "$home" "$stall" "$work/pkg-signal.rpm" 0 "$work/bin-signal"
if wait_until_rpm "$stall"; then
  HOME="$home"
  if scan_passphrase_files "while rpm --addsign runs before a signal"; then
    :
  else
    pass "another user could not read the signing passphrase before the signal"
  fi
  unset HOME
  kill -TERM -- "-$leader"
  wait "$leader" || true
  leader=
  HOME="$home"
  assert_no_leftover "after SIGTERM"
  unset HOME
else
  fail "signing script exited before the signal could be delivered"
  stop_signing
fi

# --- another user prepared the predictable path ---

sudo -n -u nobody rm -f /tmp/gpg-passphrase
sudo -n -u nobody touch /tmp/gpg-passphrase
sudo -n -u nobody chmod 666 /tmp/gpg-passphrase
home="$work/home-preowned"
stall="$work/stall-preowned"
prepare_home "$home"
mkdir -p "$stall"
start_signing "$home" "$stall" "$work/pkg-preowned.rpm" 1 "$work/bin-preowned"
if wait_until_rpm "$stall"; then
  if file_is_passphrase /tmp/gpg-passphrase && other_can_read /tmp/gpg-passphrase; then
    mode=$(stat -c %a /tmp/gpg-passphrase)
    owner=$(stat -c %U /tmp/gpg-passphrase)
    fail "script wrote the signing passphrase into a file another user created at /tmp/gpg-passphrase (owner $owner mode $mode)"
  else
    pass "script did not leave the signing passphrase in a file another user created"
  fi
  release_rpm "$stall" || true
else
  fail "signing script exited before rpm when the passphrase path already existed"
  sed "s/${passphrase}/[redacted]/g" "$work/sign.out" || true
  stop_signing
fi

# The imported key stays under the operator home. Record whether nobody can
# read it; that is separate from the passphrase file the script creates.
if other_can_read "$home/private-repo/signing/private.key"; then
  fail "another user could read the operator private key file"
else
  pass "another user could not read the operator private key file"
fi

note "failures=$failures"
exit "$failures"
