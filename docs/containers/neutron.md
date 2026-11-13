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
| BUILT_TAG | branch-3.5-latest |
| OS_VERSION | master |
| OS_CONSTRAINTS | master |
| RXT_VERSION | master |
| FLAVOR_QOS_VERSION | main |

??? example "Build Command"

    ``` bash
    docker build \
    --build-arg BUILT_TAG=branch-3.5-latest \
    --build-arg OS_VERSION=stable/2026.1 \
    --build-arg OS_CONSTRAINTS=stable/2026.1 \
    --build-arg RXT_VERSION=rxt \
    --build-arg FLAVOR_QOS_VERSION=stable/2026.1 \
    -f ContainerFiles/neutron \
    -t neutron:2026.1-flavor-qos \
    .
    ```

The `neutron-flavor-qos` package is installed from
[`rackerlabs/rxt-neutron-flavor-qos`](https://github.com/rackerlabs/rxt-neutron-flavor-qos).
For OpenStack 2026.1 builds, the image workflow selects the `stable/2026.1`
plugin branch automatically.

## Dependencies

- Builds From [OvS](ovs.md)

## Container Image

The container image is available on [Github Container Registry](https://github.com/rackerlabs/genestack-images/pkgs/container/genestack-images%2Fneutron).
