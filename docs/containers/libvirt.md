# Libvirt

The `libvirt` image is built from [ContainerFiles/libvirt](https://github.com/rackerlabs/genestack-images/blob/main/ContainerFiles/libvirt). This image has no dedicated CVE script; security updates are included during the build.

This container packages the Libvirt service for use in the stack. The build installs the required packages, applies security updates and configuration, and prepares the service for integration.

The build accepts an OpenStack release selector so the image can be tagged and
audited against the stack release it is intended to serve. Supported values are
`stable/2025.1` for Epoxy and `stable/2026.1` for Gazpacho.
Epoxy uses the standard Debian Bookworm virtualization packages. Gazpacho uses
Bookworm backports and verifies that libvirt is at least 10.0.0 and QEMU is at
least 8.2.2 during the build.

``` mermaid
graph LR
    A[Base image] --> B[Install packages]
    B --> C[Apply CVE patches]
    C --> D[Configure Libvirt]
    D --> E[Container ready]
    Ovs --> A
```

??? example "ContainerFile used for the build"

    ``` docker
    --8<-- "ContainerFiles/libvirt"
    ```

## Build Arguments

| Argument | Default |
| --- | --- |
| OS_VERSION | stable/2025.1 |
| BUILT_TAG | v3.5.1-latest |
| BUILT_TAG_2 | v1.56.1-latest |
| CACHEBUST | 0 |

??? example "Build Command"

    ``` bash
    docker build
    --build-arg OS_VERSION=stable/2026.1 \
    --build-arg BUILT_TAG=v3.5.1-latest \
    --build-arg BUILT_TAG_2=v1.56.1-latest \
    --build-arg CACHEBUST=0 \
    -f ContainerFiles/libvirt \
    -t libvirt:local \
    .
    ```

## Dependencies

- Builds From [OVS](ovs.md)
- Builds From [Libguestfs](libguestfs.md)

## Container Image

The container image is available on [Github Container Registry](https://github.com/rackerlabs/genestack-images/pkgs/container/genestack-images%2Flibvirt).
