# Magnum

The `magnum` image is built from [ContainerFiles/magnum](https://github.com/rackerlabs/genestack-images/blob/main/ContainerFiles/magnum). Security patches are applied by [scripts/magnum-cve-patching.sh](https://github.com/rackerlabs/genestack-images/blob/main/scripts/magnum-cve-patching.sh).

This container packages the Magnum service for use in the stack. The build installs the required packages, applies security updates and configuration, and prepares the service for integration.

``` mermaid
graph LR
    A[Base image] --> B[Install packages]
    B --> C[Apply CVE patches]
    C --> D[Configure Magnum]
    D --> E[Container ready]
```

??? example "ContainerFile used for the build"

    ``` docker
    --8<-- "ContainerFiles/magnum"
    ```

## Build Arguments

| Argument | Default |
| --- | --- |
| VENV_TAG | 3.12-latest |
| CACHEBUST | 0 |
| OS_VERSION | master |
| OS_CONSTRAINTS | master |
| OS_CAPI_PLUGIN_VERSION | master |

??? example "Build Command"
    ```bash
    docker build
    --build-arg VENV_TAG=3.12-latest \
    --build-arg CACHEBUST=0 \
    --build-arg OS_VERSION=master \
    --build-arg OS_CONSTRAINTS=master \
    --build-arg OS_CAPI_PLUGIN_VERSION=master \
    -f ContainerFiles/magnum .
    ```

## Dependencies

- Builds From [OpenStack Virtual Environment](openstack-venv.md)

## Container Image

The container image is available on [Github Container Registry](https://github.com/rackerlabs/genestack-images/pkgs/container/genestack-images%2Fmagnum).
