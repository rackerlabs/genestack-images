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
