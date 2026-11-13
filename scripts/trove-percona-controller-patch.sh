#!/usr/bin/env bash
# Enable Percona controller database and user operations in OpenStack Trove.
#
# Upstream Trove stable/2026.1 restricts controller-side database, schema,
# user, user-access, and root operations to datastore-version managers named
# mysql, mariadb, or postgresql. Genestack registers Percona Server with the
# manager name "percona" while mapping it to Trove's MySQL guest manager, so
# the controller rejects compatible Percona operations with HTTP 422 before an
# RPC ever reaches the guest agent. This patch adds "percona" to every
# enabled_datastore allow-list in trove/extensions/common/models.py.
#
# The patch is branch-specific. It is only applied for OS_VERSION
# stable/2026.1; every other branch (including unmaintained/2025.1 and master) is
# skipped explicitly so the behavior is never silently carried forward.
set -euo pipefail

patch_file=/opt/percona-controller-database-user-operations-stable-2026.1.patch

# Number of enabled_datastore allow-lists that must mention Percona after the
# patch, and the number of pre-patch allow-lists that must remain afterwards.
expected_percona=15
expected_old=0

case "${OS_VERSION:-master}" in
    stable/2026.1)
        : # supported branch, continue below
        ;;
    *)
        echo "No Trove Percona controller patch for ${OS_VERSION:-master}; skipping."
        exit 0
        ;;
esac

# Locate the installed trove package dynamically. trove.__file__ points at
# .../site-packages/trove/__init__.py, so the repo-style root (the directory
# that contains the top-level "trove" package) is two parents up. Never
# hard-code a pythonX.YY/site-packages path.
trove_root="$('/var/lib/openstack/bin/python' -c \
    'import pathlib, trove; print(pathlib.Path(trove.__file__).resolve().parent.parent)')"

models_py="${trove_root}/trove/extensions/common/models.py"

if [ ! -f "${models_py}" ]; then
    echo "ERROR: expected ${models_py} but it was not found." >&2
    exit 1
fi

count_percona() {
    grep -c "enabled_datastore=\['mysql', 'mariadb', 'percona'," "${models_py}" || true
}

count_old() {
    grep -c "enabled_datastore=\['mysql', 'mariadb', 'postgresql'\]" "${models_py}" || true
}

percona_now="$(count_percona)"
old_now="$(count_old)"

# Already fully patched: nothing to do.
if [ "${percona_now}" -eq "${expected_percona}" ] && [ "${old_now}" -eq "${expected_old}" ]; then
    echo "Trove Percona controller operations already enabled (${percona_now} allow-lists); skipping."
    exit 0
fi

# Partially patched is an error: we never apply on top of a half-applied tree.
if [ "${percona_now}" -ne 0 ]; then
    echo "ERROR: ${models_py} is only partially patched for Percona" \
         "(found ${percona_now} Percona allow-lists, expected 0 or" \
         "${expected_percona}). Refusing to continue." >&2
    exit 1
fi

echo "Applying Trove Percona controller patch for ${OS_VERSION:-master}."
patch --batch --forward --fuzz=0 \
    --directory="${trove_root}" --strip=1 < "${patch_file}"

# Re-count after applying and validate the exact expected shape.
percona_after="$(count_percona)"
old_after="$(count_old)"

if [ "${percona_after}" -ne "${expected_percona}" ]; then
    echo "ERROR: after patching, found ${percona_after} Percona allow-lists," \
         "expected ${expected_percona}." >&2
    exit 1
fi

if [ "${old_after}" -ne "${expected_old}" ]; then
    echo "ERROR: after patching, ${old_after} unpatched" \
         "['mysql', 'mariadb', 'postgresql'] allow-lists remain," \
         "expected ${expected_old}." >&2
    exit 1
fi

echo "Validated ${percona_after} Percona allow-lists and ${old_after} remaining old allow-lists."

# Ensure the patched module is still syntactically valid Python.
"/var/lib/openstack/bin/python" -m py_compile "${models_py}"

echo "Trove Percona controller patch complete."
