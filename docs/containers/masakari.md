# Masakari

The `masakari` image is built from [ContainerFiles/masakari](https://github.com/rackerlabs/genestack-images/blob/main/ContainerFiles/masakari). Security patches are applied by [scripts/masakari-cve-patching.sh](https://github.com/rackerlabs/genestack-images/blob/main/scripts/masakari-cve-patching.sh).

This container packages the Masakari service for use in the stack. The build installs the required packages, applies security updates and configuration, and prepares the service for integration.

``` mermaid
graph LR
    A[Base image] --> B[Install packages]
    B --> C[Apply CVE patches]
    C --> D[Configure Masakari]
    D --> E[Container ready]
```

??? example "ContainerFile used for the build"

    ``` docker
    --8<-- "ContainerFiles/masakari"
    ```

## Dependencies

- Builds From [OpenStack Virtual Environment](openstack-venv.md)
