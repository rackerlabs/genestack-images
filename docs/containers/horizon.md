# Horizon

The `horizon` image is built from [ContainerFiles/horizon](https://github.com/rackerlabs/genestack-images/blob/main/ContainerFiles/horizon). Security patches are applied by [scripts/horizon-cve-patching.sh](https://github.com/rackerlabs/genestack-images/blob/main/scripts/horizon-cve-patching.sh).

This container packages the Horizon service for use in the stack. The build installs the required packages, applies security updates and configuration, and prepares the service for integration.

``` mermaid
graph LR
    A[Base image] --> B[Install packages]
    B --> C[Apply CVE patches]
    C --> D[Configure Horizon]
    D --> E[Container ready]
    Apache --> A
```

??? example "ContainerFile used for the build"

    ``` docker
    --8<-- "ContainerFiles/horizon"
    ```

## Dependencies

- Builds From [Apache](apache.md)

## Container Image

The container image is available on [Github Container Registry](https://github.com/rackerlabs/genestack-images/pkgs/container/genestack-images%2Fhorizon).
