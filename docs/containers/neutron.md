# Neutron

The `neutron` image is built from [ContainerFiles/neutron](https://github.com/rackerlabs/genestack-images/blob/main/ContainerFiles/neutron). Security patches are applied by [scripts/neutron-cve-patching.sh](https://github.com/rackerlabs/genestack-images/blob/main/scripts/neutron-cve-patching.sh).

This container packages the Neutron service for use in the stack. The build installs the required packages, applies security updates and configuration, and prepares the service for integration.

``` mermaid
graph LR
    A[Base image] --> B[Install packages]
    B --> C[Apply CVE patches]
    C --> D[Configure Neutron]
    D --> E[Container ready]
    Ovs --> A
```

??? example "ContainerFile used for the build"

    ``` docker
    --8<-- "ContainerFiles/neutron"
    ```

## Build Arguments

| Argument | Default |
| --- | --- |
| BUILT_TAG | v3.5.1-latest |
| OS_VERSION | master |
| OS_CONSTRAINTS | master |
| RXT_VERSION | master |

??? example "Build Command"

    ``` bash
    docker build \
    --build-arg BUILT_TAG=v3.5.1-latest \
    --build-arg OS_VERSION=master \
    --build-arg OS_CONSTRAINTS=master \
    --build-arg RXT_VERSION=master \
    -f ContainerFiles/neutron \
    -t neutron:local \
    .
    ```

## Dependencies

- Builds From [OvS](ovs.md)

## Container Image

The container image is available on [Github Container Registry](https://github.com/rackerlabs/genestack-images/pkgs/container/genestack-images%2Fneutron).
