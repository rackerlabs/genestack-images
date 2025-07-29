# Ironic API

The `ironic-api` image is built from [ContainerFiles/ironic-api](https://github.com/rackerlabs/genestack-images/blob/main/ContainerFiles/ironic-api). Security patches are applied by [scripts/ironic-cve-patching.sh](https://github.com/rackerlabs/genestack-images/blob/main/scripts/ironic-cve-patching.sh).

This container packages the Ironic API service for use in the stack. The build installs the required packages, applies security updates and configuration, and prepares the service for integration.

``` mermaid
graph LR
    A[Base image] --> B[Install packages]
    B --> C[Apply CVE patches]
    C --> D[Configure Ironic API]
    D --> E[Container ready]
```

??? example "ContainerFile used for the build"

    ``` docker
    --8<-- "ContainerFiles/ironic-api"
    ```

## Dependencies

- Builds From [OpenStack Virtual Environment](openstack-venv.md)

