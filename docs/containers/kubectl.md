# kubectl

The `kubectl` image is built from [ContainerFiles/kubectl](https://github.com/rackerlabs/genestack-images/blob/main/ContainerFiles/kubectl). Security patches are applied by [scripts/kubectl-cve-patching.sh](https://github.com/rackerlabs/genestack-images/blob/main/scripts/kubectl-cve-patching.sh).

This container packages the kubectl service for use in the stack. The build installs the required packages, applies security updates and configuration, and prepares the service for integration.

``` mermaid
graph LR
    A[Base image] --> B[Install packages]
    B --> C[Apply CVE patches]
    C --> D[Configure kubectl]
    D --> E[Container ready]
```

??? example "ContainerFile used for the build"

    ``` docker
    --8<-- "ContainerFiles/kubectl"
    ```

## Build Arguments

| Argument | Default |
| --- | --- |
| KUBECTL_VERSION | v1.32.1 |
| TARGETARCH | amd64 |
| CACHEBUST | 0 |

??? example "Build Command"

    ``` bash
    docker build \
    --build-arg KUBECTL_VERSION=v1.32.1 \
    --build-arg TARGETARCH=amd64 \
    --build-arg CACHEBUST=0 \
    -f ContainerFiles/kubectl \
    -t kubectl:local \
    .
    ```

## Dependencies

- Builds From [OpenStack Virtual Environment](openstack-venv.md)

## Container Image

The container image is available on [Github Container Registry](https://github.com/rackerlabs/genestack-images/pkgs/container/genestack-images%2Fkubectl).
