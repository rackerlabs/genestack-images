# Openstack Venv

The `openstack-venv` image is built from [ContainerFiles/openstack-venv](https://github.com/rackerlabs/genestack-images/blob/main/ContainerFiles/openstack-venv). This image has no dedicated CVE script; security updates are included during the build.

This container packages the Openstack Venv service for use in the stack. The build installs the required packages, applies security updates and configuration, and prepares the service for integration.

``` mermaid
graph LR
    A[Base image] --> B[Install packages]
    B --> C[Apply CVE patches]
    C --> D[Configure Openstack Venv]
    D --> E[Container ready]
    E --> Ceph_Client
```

??? example "ContainerFile used for the build"

    ``` docker
    --8<-- "ContainerFiles/openstack-venv"
    ```

## Build Arguments

| Argument | Default |
| --- | --- |
| PYTHON_VERSION | 3.13 |
| OS_RELEASE | trixie |
| CACHEBUST | 0 |

??? example "Build Command"

    ``` bash
    docker build \
    --build-arg PYTHON_VERSION=3.13 \
    --build-arg OS_RELEASE=trixie \
    --build-arg CACHEBUST=0 \
    -f ContainerFiles/openstack-venv \
    -t openstack-venv:local \
    .
    ```

## Dependencies

- Builds From [Upstream Python](https://hub.docker.com/_/python)

## Container Image

The container image is available on [Github Container Registry](https://github.com/rackerlabs/genestack-images/pkgs/container/genestack-images%2Fopenstack-venv).
