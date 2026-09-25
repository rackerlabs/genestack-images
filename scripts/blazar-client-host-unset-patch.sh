#!/bin/bash
# Fix the reservation_host_unset OpenStackClient entry point shipped by
# python-blazarclient 4.6.0. The registered class name is singular, but the
# implementation is named UnsetAttributesHost.
#
# Idempotent: no-op if already patched or if an older client does not provide
# the command. Fails the build if 4.6.0 does not contain the expected metadata.
set -euo pipefail

ENTRY_POINTS_FILE="$(find /var/lib/openstack \
  -path '*/python_blazarclient-*.dist-info/entry_points.txt' \
  -print -quit)"

if [[ -z "${ENTRY_POINTS_FILE}" || ! -f "${ENTRY_POINTS_FILE}" ]]; then
  echo "ERROR: python-blazarclient entry_points.txt not found" >&2
  exit 1
fi

echo "Patching: ${ENTRY_POINTS_FILE}"

/var/lib/openstack/bin/python3 - "${ENTRY_POINTS_FILE}" <<'PYEOF'
import importlib.metadata
import sys

path = sys.argv[1]
version = importlib.metadata.version("python-blazarclient")
bad_entry_point = (
    "reservation_host_unset = "
    "blazarclient.v1.shell_commands.hosts:UnsetAttributeHost"
)
good_entry_point = (
    "reservation_host_unset = "
    "blazarclient.v1.shell_commands.hosts:UnsetAttributesHost"
)

with open(path, encoding="utf-8") as stream:
    contents = stream.read()

if good_entry_point in contents:
    print("python-blazarclient reservation_host_unset fix already present; skipping.")
elif contents.count(bad_entry_point) != 1:
    if version != "4.6.0":
        print(
            f"python-blazarclient {version} is not affected by the known "
            "4.6.0 entry-point typo; skipping."
        )
        sys.exit(0)
    sys.stderr.write(
        "ERROR: expected exactly one broken reservation_host_unset entry point "
        f"for python-blazarclient {version} in {path}; refusing to continue.\n"
    )
    sys.exit(1)
else:
    contents = contents.replace(bad_entry_point, good_entry_point)
    with open(path, "w", encoding="utf-8") as stream:
        stream.write(contents)
    print("Applied python-blazarclient reservation_host_unset entry-point fix.")

entry_points = importlib.metadata.distribution("python-blazarclient").entry_points
host_unset = [ep for ep in entry_points if ep.name == "reservation_host_unset"]
if len(host_unset) != 1 or host_unset[0].value != good_entry_point.split(" = ", 1)[1]:
    sys.stderr.write("ERROR: patched reservation_host_unset entry point is invalid.\n")
    sys.exit(1)

host_unset[0].load()
print("Validated reservation_host_unset entry point.")
PYEOF

echo "python-blazarclient host-unset patch complete."
