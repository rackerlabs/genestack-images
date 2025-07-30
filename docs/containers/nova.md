# Nova

The `nova` image is built from [ContainerFiles/nova](https://github.com/rackerlabs/genestack-images/blob/main/ContainerFiles/nova). Security patches are applied by [scripts/nova-cve-patching.sh](https://github.com/rackerlabs/genestack-images/blob/main/scripts/nova-cve-patching.sh).

This container packages the Nova service for use in the stack. The build installs the required packages, applies security updates and configuration, and prepares the service for integration.

``` mermaid
graph LR
    A[Base image] --> B[Install packages]
    B --> C[Apply CVE patches]
    C --> D[Configure Nova]
    D --> E[Container ready]
    Libguestfs --> A
```

??? example "ContainerFile used for the build"

    ``` docker
    --8<-- "ContainerFiles/nova"
    ```

## Dependencies

- Builds From [LibguestFS](libguestfs.md)

## Container Image

The container image is available on [Github Container Registry](https://github.com/rackerlabs/genestack-images/pkgs/container/genestack-images%2Fnova).
