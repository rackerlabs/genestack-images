# Ironic Inspector

The `ironic-inspector` image is built from [ContainerFiles/ironic-inspector](https://github.com/rackerlabs/genestack-images/blob/main/ContainerFiles/ironic-inspector). Security patches are applied by [scripts/ironic-cve-patching.sh](https://github.com/rackerlabs/genestack-images/blob/main/scripts/ironic-cve-patching.sh).

This container packages the Ironic Inspector service for use in the stack. The build installs the required packages, applies security updates and configuration, and prepares the service for integration.

``` mermaid
graph LR
    A[Base image] --> B[Install packages]
    B --> C[Apply CVE patches]
    C --> D[Configure Ironic Inspector]
    D --> E[Container ready]
```

??? example "ContainerFile used for the build"

    ``` docker
    --8<-- "ContainerFiles/ironic-inspector"
    ```

## Dependencies

- Builds From [OpenStack Virtual Environment](openstack-venv.md)

