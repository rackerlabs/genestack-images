# Apache

The `apache` image is built from [ContainerFiles/apache](https://github.com/rackerlabs/genestack-images/blob/main/ContainerFiles/apache). This image has no dedicated CVE script; security updates are included during the build.

This container packages the Apache service for use in the stack. The build installs the required packages, applies security updates and configuration, and prepares the service for integration.

``` mermaid
graph LR
    A[Base image] --> B[Install packages]
    B --> C[Apply CVE patches]
    C --> D[Configure Apache]
    D --> E[Container ready]
    E --> Keystone
```

??? example "ContainerFile used for the build"

    ``` docker
    --8<-- "ContainerFiles/apache"
    ```

## Dependencies

- Used by [Keystone](keystone.md)
