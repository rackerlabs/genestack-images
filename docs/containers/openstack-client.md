# openstack-client

The `openstack-client` image is built from [ContainerFiles/openstack-client](https://github.com/rackerlabs/genestack-images/blob/main/ContainerFiles/openstack-client). Security patches are applied by [scripts/openstack-client-cve-patching.sh](https://github.com/rackerlabs/genestack-images/blob/main/scripts/openstack-client-cve-patching.sh).

This container packages the openstack-client service for use in the stack. The build installs the required packages, applies security updates and configuration, and prepares the service for integration.

The build installs all client packages against the upper constraints of the
OpenStack release it targets. Supported `OS_VERSION` values are `stable/2025.1`
for Epoxy and `stable/2026.1` for Gazpacho.

`OS_VERSION` has no default. The release is supplied by the build workflow,
which builds every supported release on a matrix. A build that does not pass
`OS_VERSION` fails.

Published tags carry the release and the `python-openstackclient` version
resolved during the build:

| Tag | Meaning |
| --- | --- |
| `2025.1-latest` | newest build for the release |
| `2025.1-7.5.1` | the specific client release version |
| `2025.1-7.5.1-1758830017` | immutable per-build record |
| `2025.1-1758830017` | same build, retained for compatibility |

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
| VENV_TAG | 3.12-latest |
| CACHEBUST | 0 |
| OS_VERSION | none, required |

??? example "Build Command"

    ``` bash
    docker build \
    --build-arg VENV_TAG=3.12-latest \
    --build-arg OS_VERSION=stable/2026.1 \
    --build-arg CACHEBUST=0 \
    -f ContainerFiles/openstack-client \
    -t openstack-client:local \
    .
    ```

## Dependencies

- Builds From [OpenStack Virtual Environment](openstack-venv.md)

## Container Image

The container image is available on [Github Container Registry](https://github.com/rackerlabs/genestack-images/pkgs/container/genestack-images%2Fopenstack-client).
