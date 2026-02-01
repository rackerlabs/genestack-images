# alert-proxy

The `alert-proxy` image is built from [ContainerFiles/alert-proxy](https://github.com/rackerlabs/genestack-images/blob/main/ContainerFiles/alert-proxy). Security patches are applied by [scripts/alert-proxy-cve-patching.sh](https://github.com/rackerlabs/genestack-images/blob/main/scripts/alert-proxy-cve-patching.sh).

This container packages the alert-proxy service for use in the stack. The build installs the required packages, applies security updates and configuration, and prepares the service for integration.

``` mermaid
graph LR
    A[Base image] --> B[Install packages]
    B --> C[Apply CVE patches]
    C --> D[Configure alert-proxy]
    D --> E[Container ready]
```

??? example "ContainerFile used for the build"

    ``` docker
    --8<-- "ContainerFiles/alert-proxy"
    ```

## Build Arguments

| Argument | Default |
| --- | --- |
| VENV_TAG | 3.13-trixie-latest |
| CACHEBUST | 0 |

??? example "Build Command"

    ``` bash
    docker build \
    --build-arg VENV_TAG=3.13-trixie-latest \
    --build-arg CACHEBUST=0 \
    -f ContainerFiles/alert-proxy \
    -t alert-proxy:local \
    .
    ```

## Dependencies

- Builds From [OpenStack Virtual Environment](openstack-venv.md)

## Container Image

The container image is available on [Github Container Registry](https://github.com/rackerlabs/genestack-images/pkgs/container/genestack-images%2Falert-proxy).
