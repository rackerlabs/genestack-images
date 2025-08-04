# Ceph Libs

The `ceph-libs` image is built from [ContainerFiles/ceph-libs](https://github.com/rackerlabs/genestack-images/blob/main/ContainerFiles/ceph-libs). This image has no dedicated CVE script; security updates are included during the build.

This container packages the Ceph Libs service for use in the stack. The build installs the required packages, applies security updates and configuration, and prepares the service for integration.

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
    --8<-- "ContainerFiles/ceph-libs"
    ```

## Build Arguments

| Argument | Default |
| --- | --- |
| VENV_TAG | 3.12-latest |
| CACHEBUST | 0 |
| CEPH_VERSION | main |

??? example "Build Command"
    ```bash
    docker build
    --build-arg VENV_TAG=3.12-latest \
    --build-arg CACHEBUST=0 \
    --build-arg CEPH_VERSION=main \
    -f ContainerFiles/ceph-libs .
    ```

## Dependencies

- Builds From [OpenStack Virtual Environment](openstack-venv.md)

## Container Image

The container image is available on [Github Container Registry](https://github.com/rackerlabs/genestack-images/pkgs/container/genestack-images%2Fceph-libs).
