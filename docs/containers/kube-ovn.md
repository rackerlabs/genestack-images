# kube-ovn

The `kube-ovn` image is built from [ContainerFiles/kube-ovn](https://github.com/rackerlabs/genestack-images/blob/main/ContainerFiles/kube-ovn). This image has no dedicated CVE script; security updates are included during the build.

This container packages the kube-ovn service for use in the stack. The build installs the required packages, applies security updates and configuration, and prepares the service for integration.

``` mermaid
graph LR
    A[Base image] --> B[Install packages]
    B --> C[Apply CVE patches]
    C --> D[Configure kube-ovn]
    D --> E[Container ready]
    E --> Keystone
```

??? example "ContainerFile used for the build"

    ``` docker
    --8<-- "ContainerFiles/kube-ovn"
    ```

## Build Arguments

| Argument | Default |
| --- | --- |
| KUBE_OVN_VERSION | v1.14.4 |
| KUBE_OVN_VERSION_ENV | v1.14.4 |
| CACHEBUST | 0 |

??? example "Build Command"

    ``` bash
    docker build \
    --build-arg KUBE_OVN_VERSION=v1.14.4 \
    --build-arg KUBE_OVN_VERSION_ENV=v1.14.4 \
    --build-arg CACHEBUST=0 \
    -f ContainerFiles/kube-ovn \
    -t kube-ovn:local \
    .
    ```

## Dependencies

- Builds From [Upstream Debian](https://hub.docker.com/_/debian)

## Container Image

The container image is available on [Github Container Registry](https://github.com/rackerlabs/genestack-images/pkgs/container/genestack-images%2Fkube-ovn).
