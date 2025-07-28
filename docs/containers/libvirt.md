# Libvirt

The `libvirt` image is built from [ContainerFiles/libvirt](https://github.com/rackerlabs/genestack-images/blob/main/ContainerFiles/libvirt). This image has no dedicated CVE script; security updates are included during the build.

!!! example "ContainerFile used for the build"

    ``` docker
    --8<-- "ContainerFiles/libvirt"
    ```

## Dependencies

- Based on [Ovs](ovs.md)
