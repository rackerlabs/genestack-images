#!/usr/bin/env bash
# Apply the Nova resize API pre-flight checks carried by genestack-images.
set -euo pipefail

case "${OS_VERSION:-master}" in
    master)
        patch_file=/opt/resize-local-disk-preflight-master.patch
        ;;
    stable/2026.1)
        patch_file=/opt/resize-local-disk-preflight-stable-2026.1.patch
        ;;
    *)
        echo "No Nova resize pre-flight patch for ${OS_VERSION:-master}; skipping."
        exit 0
        ;;
esac

nova_root="$('/var/lib/openstack/bin/python' -c \
    'import pathlib, nova; print(pathlib.Path(nova.__file__).resolve().parent.parent)')"

if grep -q 'Unable to resize ephemeral disk down from' \
        "${nova_root}/nova/compute/api.py" && \
        grep -q 'def check_resize_local_disk_device_conflicts' \
        "${nova_root}/nova/compute/utils.py" && \
        grep -q 'hypervisor_type.lower() in LOCAL_DISK_SLOT_HYPERVISORS' \
        "${nova_root}/nova/compute/utils.py"; then
    echo "Nova resize API pre-flight checks are already present; skipping."
    exit 0
fi

echo "Applying Nova resize API pre-flight patch for ${OS_VERSION:-master}."
patch --batch --forward --fuzz=0 --directory="${nova_root}" --strip=1 \
    < "${patch_file}"

grep -q 'Unable to resize ephemeral disk down from' \
    "${nova_root}/nova/compute/api.py"
grep -q 'def check_resize_local_disk_device_conflicts' \
    "${nova_root}/nova/compute/utils.py"
grep -q 'hypervisor_type.lower() in LOCAL_DISK_SLOT_HYPERVISORS' \
    "${nova_root}/nova/compute/utils.py"
"/var/lib/openstack/bin/python" -m py_compile \
    "${nova_root}/nova/compute/api.py" \
    "${nova_root}/nova/compute/utils.py"

echo "Nova resize API pre-flight patch complete."
