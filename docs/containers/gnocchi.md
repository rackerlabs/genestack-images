# Gnocchi

The `gnocchi` image is built from [ContainerFiles/gnocchi](https://github.com/rackerlabs/genestack-images/blob/main/ContainerFiles/gnocchi). Security patches are applied by [scripts/gnocchi-cve-patching.sh](https://github.com/rackerlabs/genestack-images/blob/main/scripts/gnocchi-cve-patching.sh).

This container packages the Gnocchi metric storage service for use in the stack. The build installs the required packages, applies security updates and configuration, and prepares the service for Apache/mod_wsgi integration.

``` mermaid
graph LR
    A[Base image] --> B[Install packages]
    B --> C[Apply CVE patches]
    C --> D[Configure Gnocchi]
    D --> E[Container ready]
    Ceph_Libs --> A
```

??? example "ContainerFile used for the build"

    ``` docker
    --8<-- "ContainerFiles/gnocchi"
    ```

## Build Arguments

| Argument | Default |
| --- | --- |
| CEPH_TAG | v19.2.2-latest |
| CACHEBUST | 0 |
| GNOCCHI_VERSION | master |
| OS_CONSTRAINTS | master |

??? example "Build Command"

    ``` bash
    docker build \
    --build-arg CEPH_TAG=v19.2.2-latest \
    --build-arg CACHEBUST=0 \
    --build-arg GNOCCHI_VERSION=master \
    --build-arg OS_CONSTRAINTS=master \
    -f ContainerFiles/gnocchi \
    -t gnocchi:local \
    .
    ```

## Dependencies

- Builds From [Ceph Libs](ceph-libs.md)
- Runtime Base [Apache](apache.md)

## Container Image

The container image is available on [Github Container Registry](https://github.com/rackerlabs/genestack-images/pkgs/container/genestack-images%2Fgnocchi).
