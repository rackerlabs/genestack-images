# Keystone

The `keystone` image is built from [ContainerFiles/keystone](https://github.com/rackerlabs/genestack-images/blob/main/ContainerFiles/keystone). Security patches are applied by [scripts/keystone-cve-patching.sh](https://github.com/rackerlabs/genestack-images/blob/main/scripts/keystone-cve-patching.sh).

This container packages the Keystone service for use in the stack. The build installs the required packages, applies security updates and configuration, and prepares the service for integration.

``` mermaid
graph LR
    A[Base image] --> B[Install packages]
    B --> C[Apply CVE patches]
    C --> D[Configure Keystone]
    D --> E[Container ready]
    Apache --> A
```

??? example "ContainerFile used for the build"

    ``` docker
    --8<-- "ContainerFiles/keystone"
    ```

## Dependencies

- Builds From [Apache](apache.md)
