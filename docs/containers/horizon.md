# Horizon

The `horizon` image is built from [ContainerFiles/horizon](https://github.com/rackerlabs/genestack-images/blob/main/ContainerFiles/horizon). Security patches are applied by [scripts/horizon-cve-patching.sh](https://github.com/rackerlabs/genestack-images/blob/main/scripts/horizon-cve-patching.sh).

This container packages the Horizon service for use in the stack. The build installs the required packages, applies security updates and configuration, and prepares the service for integration.

``` mermaid
graph LR
    A[Base image] --> B[Install packages]
    B --> C[Apply CVE patches]
    C --> D[Configure Horizon]
    D --> E[Container ready]
    Apache --> A
```

??? example "ContainerFile used for the build"

    ``` docker
    --8<-- "ContainerFiles/horizon"
    ```

## Build Arguments

| Argument | Default |
| --- | --- |
| VENV_TAG | 3.13-trixie-latest |
| CACHEBUST | 0 |
| OS_VERSION | master |
| OS_CONSTRAINTS | master |

??? example "Build Command"

    ``` bash
    docker build \
    --build-arg VENV_TAG=3.13-trixie-latest \
    --build-arg CACHEBUST=0 \
    --build-arg OS_VERSION=master \
    --build-arg OS_CONSTRAINTS=master \
    -f ContainerFiles/horizon \
    -t horizon:local \
    .
    ```

## Dependencies

- Builds From [Apache](apache.md)

## Container Image

The container image is available on [Github Container Registry](https://github.com/rackerlabs/genestack-images/pkgs/container/genestack-images%2Fhorizon).
