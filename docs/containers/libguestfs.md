# Libguestfs

The `libguestfs` image is built from [ContainerFiles/libguestfs](https://github.com/rackerlabs/genestack-images/blob/main/ContainerFiles/libguestfs). This image has no dedicated CVE script; security updates are included during the build.

!!! example "ContainerFile used for the build"

    ``` docker
    --8<-- "ContainerFiles/libguestfs"
    ```

## Dependencies

- Used by [Nova](nova.md)
