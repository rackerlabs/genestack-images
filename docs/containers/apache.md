# Apache

The `apache` image is built from [ContainerFiles/apache](https://github.com/rackerlabs/genestack-images/blob/main/ContainerFiles/apache). This image has no dedicated CVE script; security updates are included during the build.

This container packages the Apache service for use in the stack. The build installs the required packages, applies security updates and configuration, and prepares the service for integration.

``` mermaid
graph LR
    A[Base image] --> B[Install packages]
    B --> C[Apply CVE patches]
    C --> D[Configure Apache]
    D --> E[Container ready]
    E --> apache
```

??? example "ContainerFile used for the build"

    ``` docker
    --8<-- "ContainerFiles/apache"
    ```

## Build Arguments

| Argument | Default |
| --- | --- |
| VENV_TAG | 3.13-trixie-latest |
| PYTHON_CONTAINER | python:3.13-slim-trixie |
| CACHEBUST | 0 |
| MOD_WSGI_VERSION | 5.0.2 |

??? example "Build Command"

    ``` bash
    docker build \
    --build-arg VENV_TAG=3.13-trixie-latest \
    --build-arg PYTHON_CONTAINER=python:3.13-slim-trixie \
    --build-arg CACHEBUST=0 \
    --build-arg MOD_WSGI_VERSION=5.0.2 \
    -f ContainerFiles/apache \
    -t apache:local \
    .
    ```

## Dependencies

- Builds From [OpenStack Virtual Environment](openstack-venv.md)

## Container Image

The container image is available on [Github Container Registry](https://github.com/rackerlabs/genestack-images/pkgs/container/genestack-images%2Fapache).
