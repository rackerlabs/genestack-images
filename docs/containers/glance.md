# Glance

The `glance` image is built from [ContainerFiles/glance](https://github.com/rackerlabs/genestack-images/blob/main/ContainerFiles/glance). Security patches are applied by [scripts/glance-cve-patching.sh](https://github.com/rackerlabs/genestack-images/blob/main/scripts/glance-cve-patching.sh).

This container packages the Glance service for use in the stack. The build installs the required packages, applies security updates and configuration, and prepares the service for integration.

``` mermaid
graph LR
    A[Base image] --> B[Install packages]
    B --> C[Apply CVE patches]
    C --> D[Configure Glance]
    D --> E[Container ready]
```

??? example "ContainerFile used for the build"

    ``` docker
    --8<-- "ContainerFiles/glance"
    ```

## Build Arguments

| Argument | Default |
| --- | --- |
| VENV_TAG | 3.13-trixie-latest |
| CACHEBUST | 0 |
| OS_VERSION | master |
| OS_CONSTRAINTS | master |
| CEPH_CLIENT_TAG | squid-3.13-trixie  |

??? example "Build Command"

    ``` bash
    docker build \
    --build-arg VENV_TAG=3.13-trixie-latest \
    --build-arg CACHEBUST=0 \
    --build-arg OS_VERSION=master \
    --build-arg OS_CONSTRAINTS=master \
    --build-arg CEPH_CLIENT_TAG=squid-3.13-trixie \
    -f ContainerFiles/glance \
    -t glance:local \
    .
    ```

## Dependencies

- Builds From [OpenStack Virtual Environment](openstack-venv.md)

## Container Image

The container image is available on [Github Container Registry](https://github.com/rackerlabs/genestack-images/pkgs/container/genestack-images%2Fglance).
