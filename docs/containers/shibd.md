# Shibd

The `shibd` image is built from [ContainerFiles/shibd](https://github.com/rackerlabs/genestack-images/blob/main/ContainerFiles/shibd). This image has no dedicated CVE script; security updates are included during the build.

This container packages the Shibd service for use in the stack. The build installs the required packages, applies security updates and configuration, and prepares the service for integration.

``` mermaid
graph LR
    A[Base image] --> B[Install packages]
    B --> C[Apply CVE patches]
    C --> D[Configure Shibd]
    D --> E[Container ready]
```

??? example "ContainerFile used for the build"

    ``` docker
    --8<-- "ContainerFiles/shibd"
    ```

## Dependencies

- Builds From [Upstream Debian](https://hub.docker.com/_/debian)

## Container Image

The container image is available on [Github Container Registry](https://github.com/rackerlabs/genestack-images/pkgs/container/genestack-images%2Fshibd).
