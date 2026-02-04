# Keystone

The `keystone` image is built from [ContainerFiles/keystone](https://github.com/rackerlabs/genestack-images/blob/main/ContainerFiles/keystone). Security patches are applied by [scripts/keystone-cve-patching.sh](https://github.com/rackerlabs/genestack-images/blob/main/scripts/keystone-cve-patching.sh).

This container packages the Keystone service for use in the stack. The build installs the required packages, applies security updates and configuration, and prepares the service for integration.

``` mermaid
graph LR
    A[Base image] --> B[Install packages]
    B --> C[Apply CVE patches]
    C --> D[Configure Keystone]
    D --> E[Container ready]
    Apache --> A
```

??? example "ContainerFile used for the build"

    ``` docker
    --8<-- "ContainerFiles/keystone"
    ```

## Build Arguments

| Argument | Default |
| --- | --- |
| VENV_TAG | 3.13-trixie-latest |
| CACHEBUST | 0 |
| OS_VERSION | master |
| OS_CONSTRAINTS | master |
| RXT_VERSION | main |
| MOD_WSGI_VERSION | 5.0.2 |

??? example "Build Command"

    ``` bash
    docker build \
    --build-arg VENV_TAG=3.13-trixie-latest \
    --build-arg CACHEBUST=0 \
    --build-arg OS_VERSION=master \
    --build-arg OS_CONSTRAINTS=master \
    --build-arg RXT_VERSION=main \
    --build-arg MOD_WSGI_VERSION=5.0.2 \
    -f ContainerFiles/keystone \
    -t keystone:local \
    .
    ```

## Dependencies

- Builds From [Apache](apache.md)

## Container Image

The container image is available on [Github Container Registry](https://github.com/rackerlabs/genestack-images/pkgs/container/genestack-images%2Fkeystone).
