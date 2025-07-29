# Skyline

The `skyline` image is built from [ContainerFiles/skyline](https://github.com/rackerlabs/genestack-images/blob/main/ContainerFiles/skyline). It packages the RackerLabs fork of Skyline and applies security fixes with [scripts/skyline-cve-patching.sh](https://github.com/rackerlabs/genestack-images/blob/main/scripts/skyline-cve-patching.sh).

This container packages the Skyline service for use in the stack. The build installs the required packages, applies security updates and configuration, and prepares the service for integration.

``` mermaid
graph LR
    A[Base image] --> B[Install packages]
    B --> C[Apply CVE patches]
    C --> D[Configure Skyline]
    D --> E[Container ready]
```

??? example "ContainerFile used for the build"

    ``` docker
    --8<-- "ContainerFiles/skyline"
    ```

## Dependencies

- Builds From [OpenStack Virtual Environment](openstack-venv.md)
