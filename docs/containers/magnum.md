# Magnum

The `magnum` image is built from [ContainerFiles/magnum](https://github.com/rackerlabs/genestack-images/blob/main/ContainerFiles/magnum). Security patches are applied by [scripts/magnum-cve-patching.sh](https://github.com/rackerlabs/genestack-images/blob/main/scripts/magnum-cve-patching.sh).

This container packages the Magnum service for use in the stack. The build installs the required packages, applies security updates and configuration, and prepares the service for integration.

``` mermaid
graph LR
    A[Base image] --> B[Install packages]
    B --> C[Apply CVE patches]
    C --> D[Configure Magnum]
    D --> E[Container ready]
```

??? example "ContainerFile used for the build"

    ``` docker
    --8<-- "ContainerFiles/magnum"
    ```
