# Libvirt

The `libvirt` image is built from [ContainerFiles/libvirt](https://github.com/rackerlabs/genestack-images/blob/main/ContainerFiles/libvirt). This image has no dedicated CVE script; security updates are included during the build.

This container packages the Libvirt service for use in the stack. The build installs the required packages, applies security updates and configuration, and prepares the service for integration.

``` mermaid
graph LR
    A[Base image] --> B[Install packages]
    B --> C[Apply CVE patches]
    C --> D[Configure Libvirt]
    D --> E[Container ready]
    Ovs --> A
```

??? example "ContainerFile used for the build"

    ``` docker
    --8<-- "ContainerFiles/libvirt"
    ```

## Dependencies

- Based on [Ovs](ovs.md)
