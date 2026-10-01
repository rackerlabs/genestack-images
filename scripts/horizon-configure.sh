#!/usr/bin/env bash
#
# horizon-configure.sh
#
# Wires pip-installed Horizon dashboard plugins into the running dashboard and
# generates offline-compressed static assets at image-build time.
#
# Why this is needed:
#   Horizon only auto-discovers pluggable panels from two directories:
#     openstack_dashboard/enabled/        (core panels, shipped with horizon)
#     openstack_dashboard/local/enabled/  (where plugins must place their files)
#   A pip-installed plugin (heat_dashboard, octavia_dashboard, ...) ships its
#   panel registration files in <plugin>/enabled/_NNNN_*.py inside its OWN
#   package directory, which Horizon does NOT scan. Each plugin's enabled files
#   (and its local_settings.d snippets and policy files) must be linked into the
#   openstack_dashboard tree. This mirrors what openstack-helm-images does in its
#   horizon/configure_horizon.sh.
#
# This script auto-discovers every installed plugin that ships an enabled/ dir,
# so it stays correct regardless of the plugins' (irregular) import names.

set -euo pipefail

# Resolve the venv's site-packages (the image installs horizon into
# /var/lib/openstack, a venv on PATH).
SITE_PACKAGES="$(python -c 'from sysconfig import get_path; print(get_path("purelib"))')"
OPENSTACK_DASHBOARD="${SITE_PACKAGES}/openstack_dashboard"

if [ ! -d "${OPENSTACK_DASHBOARD}" ]; then
    echo "ERROR: openstack_dashboard not found under ${SITE_PACKAGES}" >&2
    exit 1
fi

LOCAL_ENABLED="${OPENSTACK_DASHBOARD}/local/enabled"
LOCAL_SETTINGS_D="${OPENSTACK_DASHBOARD}/local/local_settings.d"
CONF_DIR="${OPENSTACK_DASHBOARD}/conf"
# NOTE: STATIC_ROOT must live under /var/lib/openstack. The horizon image's
# final stage only copies /var/lib/openstack from the build stage, and the
# apache base image deletes /var/www/html, so anything written outside the venv
# tree at build time would be lost in the final image.
STATIC_ROOT="${HORIZON_STATIC_ROOT:-/var/lib/openstack/static/horizon}"

mkdir -p "${LOCAL_ENABLED}" "${LOCAL_SETTINGS_D}" "${CONF_DIR}" "${STATIC_ROOT}"

link_into() {
    # link_into <source-file> <target-dir>
    local src="$1" dst_dir="$2"
    local base
    base="$(basename "${src}")"
    ln -sf "${src}" "${dst_dir}/${base}"
}

echo "==> Linking dashboard plugin panels into ${LOCAL_ENABLED}"
# Every installed package except openstack_dashboard itself; look in both the
# conventional enabled/ and local/enabled/ locations plugins may ship.
for pkg_dir in "${SITE_PACKAGES}"/*/; do
    pkg_name="$(basename "${pkg_dir}")"
    [ "${pkg_name}" = "openstack_dashboard" ] && continue

    for enabled_subdir in "enabled" "local/enabled"; do
        panel_dir="${pkg_dir}${enabled_subdir}"
        [ -d "${panel_dir}" ] || continue
        # Only pluggable panel files (prefixed _1.._9); skip __init__.py etc.
        shopt -s nullglob
        for panel in "${panel_dir}"/_[1-9]*.py; do
            echo "    + ${pkg_name}: $(basename "${panel}")"
            link_into "${panel}" "${LOCAL_ENABLED}"
        done
        shopt -u nullglob
    done

    # Per-plugin Django settings snippets.
    settings_dir="${pkg_dir}local/local_settings.d"
    if [ -d "${settings_dir}" ]; then
        shopt -s nullglob
        for snippet in "${settings_dir}"/*; do
            link_into "${snippet}" "${LOCAL_SETTINGS_D}"
        done
        shopt -u nullglob
    fi

    # Per-plugin policy files.
    plugin_conf="${pkg_dir}conf"
    if [ -d "${plugin_conf}" ]; then
        shopt -s nullglob
        for policy in "${plugin_conf}"/*.json "${plugin_conf}"/*.yaml; do
            link_into "${policy}" "${CONF_DIR}"
        done
        if [ -d "${plugin_conf}/default_policies" ]; then
            mkdir -p "${CONF_DIR}/default_policies"
            for policy in "${plugin_conf}/default_policies"/*.json "${plugin_conf}/default_policies"/*.yaml; do
                link_into "${policy}" "${CONF_DIR}/default_policies"
            done
        fi
        shopt -u nullglob
    fi
done

# Build-only settings module: import the real horizon settings, then force the
# offline-compress knobs and STATIC_ROOT needed to generate assets. This lives
# in a throwaway dir on PYTHONPATH so nothing leaks into the runtime image's
# local_settings (genestack supplies its own local_settings at deploy time).
BUILD_SETTINGS_DIR="$(mktemp -d)"
cat > "${BUILD_SETTINGS_DIR}/_horizon_build_settings.py" <<EOF
from openstack_dashboard.settings import *  # noqa: F401,F403
COMPRESS_OFFLINE = True
STATIC_ROOT = "${STATIC_ROOT}"
EOF

export PYTHONPATH="${BUILD_SETTINGS_DIR}:${PYTHONPATH:-}"
export DJANGO_SETTINGS_MODULE="_horizon_build_settings"

# horizon's manage.py lives at the sdist root and is NOT installed into
# site-packages, so invoke Django's admin entrypoint directly. collectstatic and
# compress only need DJANGO_SETTINGS_MODULE set.
echo "==> Collecting static assets"
django-admin collectstatic --noinput --clear

echo "==> Generating offline-compressed assets"
django-admin compress --force

rm -rf "${BUILD_SETTINGS_DIR}"

# A persisted SECRET_KEY or stale lock from the build must not leak into the
# image; Horizon regenerates/handles these at runtime.
rm -f "${OPENSTACK_DASHBOARD}/local/.secret_key_store"
shopt -s nullglob
for lock in "${OPENSTACK_DASHBOARD}/local"/*.lock; do
    rm -f "${lock}"
done
shopt -u nullglob

echo "==> horizon-configure.sh complete"
