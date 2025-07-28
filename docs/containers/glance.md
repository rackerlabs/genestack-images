# Glance

The `glance` image is built from [ContainerFiles/glance](https://github.com/rackerlabs/genestack-images/blob/main/ContainerFiles/glance). Security patches are applied by [scripts/glance-cve-patching.sh](https://github.com/rackerlabs/genestack-images/blob/main/scripts/glance-cve-patching.sh).

This container packages the Glance service for use in the stack. The build installs the required packages, applies security updates and configuration, and prepares the service for integration.

``` mermaid
graph LR
    A[Base image] --> B[Install packages]
    B --> C[Apply CVE patches]
    C --> D[Configure Glance]
    D --> E[Container ready]
```

??? example "ContainerFile used for the build"

    ``` docker
    --8<-- "ContainerFiles/glance"
    ```

## Dependencies

- Builds From [OpenStack Virtual Environment](openstack-venv.md)
