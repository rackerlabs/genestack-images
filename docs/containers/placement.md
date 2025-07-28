# Placement

The `placement` image is built from [ContainerFiles/placement](https://github.com/rackerlabs/genestack-images/blob/main/ContainerFiles/placement). Security patches are applied by [scripts/placement-cve-patching.sh](https://github.com/rackerlabs/genestack-images/blob/main/scripts/placement-cve-patching.sh).

This container packages the Placement service for use in the stack. The build installs the required packages, applies security updates and configuration, and prepares the service for integration.

``` mermaid
graph LR
    A[Base image] --> B[Install packages]
    B --> C[Apply CVE patches]
    C --> D[Configure Placement]
    D --> E[Container ready]
```

??? example "ContainerFile used for the build"

    ``` docker
    --8<-- "ContainerFiles/placement"
    ```

## Dependencies

- Builds From [OpenStack Virtual Environment](openstack-venv.md)
- Based on [Upstream Debian Slim](https://hub.docker.com/_/debian/tags?name=slim)
