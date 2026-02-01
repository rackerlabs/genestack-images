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
| BUILT_TAG | v1.56.2-latest |
| OS_VERSION | master |
| OS_CONSTRAINTS | master |
| NOVNC_VERSION | master |
| CEPH_CLIENT_TAG | squid-3.13-trixie  |

??? example "Build Command"

    ``` bash
    docker build \
    --build-arg BUILT_TAG=v1.56.2-latest \
    --build-arg OS_VERSION=master \
    --build-arg OS_CONSTRAINTS=master \
    --build-arg NOVNC_VERSION=master \
    --build-arg CEPH_CLIENT_TAG=squid-3.13-trixie \
    -f ContainerFiles/nova \
    -t nova:local \
    .
    ```

## Dependencies

- Builds From [LibguestFS](libguestfs.md)

## Container Image

The container image is available on [Github Container Registry](https://github.com/rackerlabs/genestack-images/pkgs/container/genestack-images%2Fnova).
