# Nova

The `nova` image is built from [ContainerFiles/nova](https://github.com/rackerlabs/genestack-images/blob/main/ContainerFiles/nova). Security patches are applied by [scripts/nova-cve-patching.sh](https://github.com/rackerlabs/genestack-images/blob/main/scripts/nova-cve-patching.sh).

This container packages the Nova service for use in the stack. The build installs the required packages, applies security updates and configuration, and prepares the service for integration.

``` mermaid
graph LR
    A[Base image] --> B[Install packages]
    B --> C[Apply CVE patches]
    C --> D[Configure Nova]
    D --> E[Container ready]
    Libguestfs --> A
```

??? example "ContainerFile used for the build"

    ``` docker
    --8<-- "ContainerFiles/nova"
    ```

## Build Arguments

| Argument | Default |
| --- | --- |
| BUILT_TAG | v1.56.1-latest |
| OS_VERSION | master |
| OS_CONSTRAINTS | master |
| NOVA_REPOSITORY | https://opendev.org/openstack/nova.git |
| NOVA_FLAVOR_QOS_REPOSITORY | https://github.com/rackerlabs/rxt-nova-flavor-qos.git |
| NOVNC_VERSION | master |

`rxt-nova-flavor-qos` uses `OS_VERSION`, keeping its branch aligned with the
Nova branch selected by the build workflow (for example, `stable/2026.1`).

??? example "Build Command"

    ``` bash
    docker build \
    --build-arg BUILT_TAG=v1.56.1-latest \
    --build-arg OS_VERSION=stable/2026.1 \
    --build-arg OS_CONSTRAINTS=stable/2026.1 \
    --build-arg NOVA_REPOSITORY=https://opendev.org/openstack/nova.git \
    --build-arg NOVA_FLAVOR_QOS_REPOSITORY=https://github.com/rackerlabs/rxt-nova-flavor-qos.git \
    --build-arg NOVNC_VERSION=master \
    -f ContainerFiles/nova \
    -t nova:2026.1-flavor-qos \
    .
    ```

The Nova and `rxt-nova-flavor-qos` repositories are installed into the same
`/var/lib/openstack` virtual environment.

The image preserves the stock executable as `nova-compute.stock` and links
`nova-compute` to the adapter entry point:

```text
/var/lib/openstack/bin/nova-compute -> nova-flavor-qos-compute
```

This lets the existing Helm compute workload continue invoking `nova-compute`
without a chart change. API, conductor, scheduler, and utility workloads use
their normal Nova executables and are unaffected. A compute workload can use
`/var/lib/openstack/bin/nova-compute.stock` as an explicit operational
rollback without rebuilding the image.

## Dependencies

- Builds From [LibguestFS](libguestfs.md)

## Container Image

The container image is available on [Github Container Registry](https://github.com/rackerlabs/genestack-images/pkgs/container/genestack-images%2Fnova).
