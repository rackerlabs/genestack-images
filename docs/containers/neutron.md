# Neutron

The `neutron` image is built from [ContainerFiles/neutron](https://github.com/rackerlabs/genestack-images/blob/main/ContainerFiles/neutron). Security patches are applied by [scripts/neutron-cve-patching.sh](https://github.com/rackerlabs/genestack-images/blob/main/scripts/neutron-cve-patching.sh).

This container packages the Neutron service for use in the stack. The build installs the required packages, applies security updates and configuration, and prepares the service for integration.

``` mermaid
graph LR
    A[Base image] --> B[Install packages]
    B --> C[Apply CVE patches]
    C --> D[Configure Neutron]
    D --> E[Container ready]
    Ovs --> A
```

??? example "ContainerFile used for the build"

    ``` docker
    --8<-- "ContainerFiles/neutron"
    ```

## Dependencies

- Builds From [OvS](ovs.md)
