# Neutron

The `neutron` image is built from [ContainerFiles/neutron](https://github.com/rackerlabs/genestack-images/blob/main/ContainerFiles/neutron). Security patches are applied by [scripts/neutron-cve-patching.sh](https://github.com/rackerlabs/genestack-images/blob/main/scripts/neutron-cve-patching.sh).

!!! example "ContainerFile used for the build"

    ``` docker
    --8<-- "ContainerFiles/neutron"
    ```

## Dependencies

- Based on [Ovs](ovs.md)
