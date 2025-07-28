# Nova

The `nova` image is built from [ContainerFiles/nova](https://github.com/rackerlabs/genestack-images/blob/main/ContainerFiles/nova). Security patches are applied by [scripts/nova-cve-patching.sh](https://github.com/rackerlabs/genestack-images/blob/main/scripts/nova-cve-patching.sh).

!!! example "ContainerFile used for the build"

    ``` docker
    --8<-- "ContainerFiles/nova"
    ```

## Dependencies

- Based on [Libguestfs](libguestfs.md)
