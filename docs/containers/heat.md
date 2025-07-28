# Heat

The `heat` image is built from [ContainerFiles/heat](https://github.com/rackerlabs/genestack-images/blob/main/ContainerFiles/heat). Security patches are applied by [scripts/heat-cve-patching.sh](https://github.com/rackerlabs/genestack-images/blob/main/scripts/heat-cve-patching.sh).

This container packages the Heat service for use in the stack. The build installs the required packages, applies security updates and configuration, and prepares the service for integration.

``` mermaid
graph LR
    A[Base image] --> B[Install packages]
    B --> C[Apply CVE patches]
    C --> D[Configure Heat]
    D --> E[Container ready]
```

??? example "ContainerFile used for the build"

    ``` docker
    --8<-- "ContainerFiles/heat"
    ```
