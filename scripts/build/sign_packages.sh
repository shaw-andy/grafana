#!/bin/bash

set -e

_files=$*

if [ -z "$_files" ]; then
    echo "_files (arg 1) has to be set"
    exit 1
fi

if [ -z "$GPG_KEY_PASSWORD" ]; then
    echo "GPG_KEY_PASSWORD has to be set"
    exit 1
fi

passphrase_dir=
cleanup() {
    if [ -n "$passphrase_dir" ]; then
        rm -rf "$passphrase_dir"
    fi
}
trap cleanup EXIT
# Without these, bash exits on the signal without running the EXIT trap.
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

gpg --batch --allow-secret-key-import --import ~/private-repo/signing/private.key

# Every gpg run that rpm starts opens this file, so it has to exist for the
# whole loop; keep it in a fresh directory only this user can enter.
passphrase_dir=$(mktemp -d)
passphrase_file="$passphrase_dir/passphrase"
(umask 077 && set -o noclobber && printf '%s\n' "$GPG_KEY_PASSWORD" > "$passphrase_file")

cp ./scripts/build/rpmmacros ~/.rpmmacros

for package in $_files; do
    [ -e "$package" ] || continue
    rpm --define "_gpg_passphrase_file $passphrase_file" --addsign "$package"
done
