# Container source patches

This file records source patches applied while building Genestack container
images. Review every entry when its upstream project branch or container
version changes. A patch must not be silently carried to a new branch: confirm
whether the change has landed upstream, remove it when it is no longer needed,
or rebase it and add the new branch-specific artifact here.

Dependency overrides maintained by the `scripts/*-cve-patching.sh` scripts are
not source patches and are tracked in those scripts instead.

## Active patches

### Nova resize local-disk API pre-flight checks

| Field | Value |
| --- | --- |
| Status | Active |
| Added | 2026-10-15 |
| Image | `nova` |
| Upstream project | `openstack/nova` |
| Supported branches | `master`, `stable/2026.1` |
| Patched files | `nova/compute/api.py`, `nova/compute/utils.py` |
| Build integration | `ContainerFiles/nova` |
| Apply script | `scripts/nova-resize-preflight-patch.sh` |
| Patch artifacts | `patches/nova/resize-local-disk-preflight-master.patch`, `patches/nova/resize-local-disk-preflight-stable-2026.1.patch` |

#### Purpose

Fail resize requests in the Nova API before instance metadata, task state, and
quota side effects occur when the requested flavor cannot be represented by
the existing local-disk layout.

The pre-flight check returns HTTP 400 through Nova's existing
`CannotResizeDisk` handling when:

- a flavor would reduce the ephemeral disk size on the libvirt-family
  hypervisors (`kvm`, `qemu`, or `parallels`), accepting the uppercase
  hypervisor types reported by libvirt-backed compute nodes; or
- a newly required ephemeral or swap disk device slot conflicts with the
  device name of an attached Cinder volume.

This patch intentionally contains only API pre-flight runtime changes. It does
not change compute-manager or libvirt resize behavior.

#### Branch-specific artifacts

The two artifacts implement the same behavior but are generated separately
because the surrounding Nova API code differs between branches. The apply
script selects an artifact from `OS_VERSION`, applies it with zero fuzz, checks
for both implementation markers, and compiles the modified Python modules.
Unsupported versions are left unpatched.

The artifacts were initially validated against these upstream revisions:

| Branch | Validated revision |
| --- | --- |
| `master` | `9c9296e6e765a8dde029e0c7987e5970f66204b4` |
| `stable/2026.1` | `a858936e70bbe04e06fd5d47d840592a3d2d1fde` |

#### Upgrade reconciliation

Before changing `OS_VERSION` or adding a new Nova branch to the image build:

1. Check whether upstream Nova now performs both pre-flight validations. If it
   does, remove the applicable patch artifact and branch case rather than
   applying the behavior twice.
2. If the behavior is still missing, create a patch against the exact new
   upstream branch. Do not reuse an existing branch artifact without verifying
   its context and semantics.
3. Add the artifact under `patches/nova/`, add an explicit `OS_VERSION` case to
   `scripts/nova-resize-preflight-patch.sh`, and update this entry.
4. Apply the patch with `--fuzz=0` to a clean checkout or archive of the target
   revision and compile the modified Python files.
5. Build the Nova image for the new version and exercise both rejected resize
   scenarios, a valid resize, and a version for which no patch is expected.
6. Record the tested upstream revision in this document.

If an artifact stops applying, treat that as an upgrade reconciliation failure;
do not relax the zero-fuzz requirement to make the image build pass.

### Trove Percona controller database and user operations

| Field | Value |
| --- | --- |
| Status | Active |
| Added | 2026-11-07 |
| Image | `trove` |
| Upstream project | `openstack/trove` |
| Supported branch | `stable/2026.1` only |
| Patched file | `trove/extensions/common/models.py` |
| Build integration | `ContainerFiles/trove` |
| Apply script | `scripts/trove-percona-controller-patch.sh` |
| Patch artifact | `patches/trove/percona-controller-database-user-operations-stable-2026.1.patch` |

#### Purpose

Upstream Trove's controller-side extension models restrict database, schema,
user, user-access, and root operations to datastore-version managers named
`mysql`, `mariadb`, or `postgresql`. Each operation calls `load_and_verify`
with an allow-list such as:

```python
enabled_datastore=['mysql', 'mariadb', 'postgresql']
```

Genestack intentionally registers Percona Server with the manager name
`percona` while mapping that manager to Trove's MySQL guest manager. Because
`percona` is not in the controller allow-lists, the Trove API rejects the
request before an RPC reaches the guest agent and returns:

```
Operation not supported for datastore percona. (HTTP 422)
```

Percona Server is MySQL wire- and protocol-compatible and is driven by the
same Trove MySQL guest manager, so the database, schema, user, user-access,
and root operations that Trove already enables for MySQL and MariaDB are valid
for Percona. The patch adds `percona` to every `enabled_datastore` allow-list
in `trove/extensions/common/models.py`, enabling the same controller
operations for the Percona datastore.

This patch contains only controller allow-list changes. It is a controller
image/package patch, not a Trove guest image patch, and it does not change
guest-agent behavior.

#### Zero-fuzz and validation behavior

`scripts/trove-percona-controller-patch.sh` only acts when
`OS_VERSION=stable/2026.1`; every other branch (including `unmaintained/2025.1` and
`master`) is skipped explicitly so the change is never silently carried to a
branch it was not generated against.

The script locates the installed package dynamically with
`/var/lib/openstack/bin/python` and `trove.__file__` (it does not hard-code a
`pythonX.YY/site-packages` path), detects an already fully patched tree and
skips, and fails if it finds a partially patched tree. It applies the artifact
with:

```
patch --batch --forward --fuzz=0 --directory="${trove_root}" --strip=1 < "${patch_file}"
```

After applying, it validates that exactly 15 `enabled_datastore` allow-lists
include `percona` and that zero pre-patch
`['mysql', 'mariadb', 'postgresql']` allow-lists remain, then runs
`py_compile` on the modified `models.py`. If the patch cannot apply completely,
or the count of patched allow-lists is anything other than 15, the build fails.

#### Validated upstream revision

The artifact was generated and validated against the `stable/2026.1` branch
head of `openstack/trove` at revision
`fc7ce52e189eed36dd4e1d7116f9d75bb89bcaae`. That revision contains exactly 15
`enabled_datastore=['mysql', 'mariadb', 'postgresql']` allow-lists in
`trove/extensions/common/models.py`, and the patch applies to it cleanly with
`--fuzz=0`.

#### Upgrade reconciliation

Before changing `OS_VERSION` or adding a new Trove branch to the image build:

1. Check whether upstream Trove now accepts the `percona` manager in the
   controller operation allow-lists (or has otherwise removed the controller
   allow-list restriction). If it has, remove this patch artifact and the
   `stable/2026.1` case in `scripts/trove-percona-controller-patch.sh` rather
   than applying the change twice.
2. If the restriction still exists, regenerate the patch against the exact new
   upstream branch. Do not reuse this `stable/2026.1` artifact without
   verifying the surrounding context and the allow-list count.
3. Add the artifact under `patches/trove/`, add an explicit `OS_VERSION` case
   to `scripts/trove-percona-controller-patch.sh`, update the expected
   allow-list count if upstream added or removed call sites, and update this
   entry.
4. Apply the patch with `--fuzz=0` to a clean checkout or archive of the
   target revision, confirm it changes exactly the expected number of
   allow-lists, and compile the modified Python file.
5. Build the Trove image for the new version and confirm Percona database and
   user operations no longer return HTTP 422, and that a version for which no
   patch is expected remains unpatched.
6. Record the tested upstream revision in this document.

If the artifact stops applying, treat that as an upgrade reconciliation
failure; do not relax the zero-fuzz requirement to make the image build pass.
