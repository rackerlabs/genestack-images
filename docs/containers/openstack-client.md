# openstack-client

The `openstack-client` image is built from [ContainerFiles/openstack-client](https://github.com/rackerlabs/genestack-images/blob/main/ContainerFiles/openstack-client). Security patches are applied by [scripts/openstack-client-cve-patching.sh](https://github.com/rackerlabs/genestack-images/blob/main/scripts/openstack-client-cve-patching.sh).

This container packages the openstack-client service for use in the stack. The build installs the required packages, applies security updates and configuration, and prepares the service for integration.

``` mermaid
graph LR
    A[Base image] --> B[Install packages]
    B --> C[Apply CVE patches]
    C --> D[Configure openstack-client]
    D --> E[Container ready]
```

??? example "ContainerFile used for the build"

    ``` docker
    --8<-- "ContainerFiles/openstack-client"
    ```

## Build Arguments

| Argument | Default |
| --- | --- |
| VENV_TAG | 3.13-trixie-latest |
| CACHEBUST | 0 |
| OS_CONSTRAINTS | master |

??? example "Build Command"

    ``` bash
    docker build \
    --build-arg VENV_TAG=3.13-trixie-latest \
    --build-arg CACHEBUST=0 \
    -f ContainerFiles/openstack-client \
    -t openstack-client:local \
    .
    ```

## Dependencies

- Builds From [OpenStack Virtual Environment](openstack-venv.md)

## Container Image

The container image is available on [Github Container Registry](https://github.com/rackerlabs/genestack-images/pkgs/container/genestack-images%2Fopenstack-client).
