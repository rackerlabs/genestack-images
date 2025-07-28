# Ovs

The `ovs` image is built from [ContainerFiles/ovs](https://github.com/rackerlabs/genestack-images/blob/main/ContainerFiles/ovs). This image has no dedicated CVE script; security updates are included during the build.

!!! example "ContainerFile used for the build"

    ``` docker
    --8<-- "ContainerFiles/ovs"
    ```

## Dependencies

- Used by [Libvirt](libvirt.md), [Neutron](neutron.md)
