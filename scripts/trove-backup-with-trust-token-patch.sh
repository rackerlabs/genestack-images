#!/usr/bin/env bash
# Apply the Trove backup with trust token patch.
set -euo pipefail

case "${OS_VERSION:-master}" in
    master)
        patch_file=/opt/backup-with-trust-token-master.patch
        ;;
    stable/2026.1)
        patch_file=/opt/backup-with-trust-token-stable-2026.1.patch
        ;;
    *)
        echo "No Trove backup with trust token patch for ${OS_VERSION:-master}; skipping."
        exit 0
        ;;
esac

trove_root="$('/var/lib/openstack/bin/python' -c \
    'import pathlib, trove; print(pathlib.Path(trove.__file__).resolve().parent)')"

echo "[DEBUG] trove_root: ${trove_root}"
echo "[DEBUG] ls -alh ${trove_root}/backup:"
ls -alh ${trove_root}/backup
echo "[DEBUG] ls -alh ${trove_root}/backup/storage:"
ls -alh ${trove_root}/backup/storage

if grep -q 'Trust tokens cannot be re-scoped' \
        "${trove_root}/backup/storage/swift.py"; then
    echo "Trove backup with trust token patch already present; skipping."
    exit 0
fi

echo "Applying Trove backup with trust token patch for ${OS_VERSION:-master}."
patch --batch --forward --fuzz=0 --directory="${trove_root}" --strip=1 \
    < "${patch_file}"

grep -q 'Trust tokens cannot be re-scoped' \
    "${trove_root}/backup/storage/swift.py"
"/var/lib/openstack/bin/python" -m py_compile \
    "${trove_root}/backup/storage/swift.py"

echo "Trove backup with trust token patch complete."
