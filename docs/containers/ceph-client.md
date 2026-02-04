# Ceph Libs

The `ceph-client` image is built from [ContainerFiles/ceph-client](https://github.com/rackerlabs/genestack-images/blob/main/ContainerFiles/ceph-client). This image has no dedicated CVE script; security updates are included during the build.

This container packages the Ceph client for use in the stack. The build installs the required packages, applies security updates and configuration, and prepares the service for integration.

``` mermaid
graph LR
    A[Base image] --> B[Install packages]
    B --> C[Apply CVE patches]
    C --> D[Configure Ceph Libs]
    D --> E[Container ready]
    Openstack_Venv --> A
```

??? example "ContainerFile used for the build"

    ``` docker
    --8<-- "ContainerFiles/ceph-client"
    ```

## Build Arguments

| Argument | Default |
| --- | --- |
| VENV_TAG | 3.13-trixie-latest |
| CACHEBUST | 0 |
| CEPH_REPO | pve |
| CEPH_VERSION | squid |
| OS_RELEASE | trixie |

??? example "Build Command"

    ``` bash
    docker build \
    --build-arg VENV_TAG=3.13-trixie-latest \
    --build-arg CACHEBUST=0 \
    --build-arg CEPH_VERSION=19.2.3-pve2 \
    -f ContainerFiles/ceph-client \
    -t ceph-client:local \
    .
    ```

## Dependencies

- Builds From [OpenStack Virtual Environment](openstack-venv.md)

## Container Image

The container image is available on [Github Container Registry](https://github.com/rackerlabs/genestack-images/pkgs/container/genestack-images%2Fceph-client).
