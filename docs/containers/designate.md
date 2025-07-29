# Designate

The `designate` image is built from [ContainerFiles/designate](https://github.com/rackerlabs/genestack-images/blob/main/ContainerFiles/designate). Security patches are applied by [scripts/designate-cve-patching.sh](https://github.com/rackerlabs/genestack-images/blob/main/scripts/designate-cve-patching.sh).

This container packages the Designate service for use in the stack. The build installs the required packages, applies security updates and configuration, and prepares the service for integration.

``` mermaid
graph LR
    A[Base image] --> B[Install packages]
    B --> C[Apply CVE patches]
    C --> D[Configure Designate]
    D --> E[Container ready]
```

??? example "ContainerFile used for the build"

    ``` docker
    --8<-- "ContainerFiles/designate"
    ```

## Dependencies

- Builds From [OpenStack Virtual Environment](openstack-venv.md)
