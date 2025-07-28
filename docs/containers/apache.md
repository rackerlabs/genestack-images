# Apache

The `apache` image is built from [ContainerFiles/apache](https://github.com/rackerlabs/genestack-images/blob/main/ContainerFiles/apache). This image has no dedicated CVE script; security updates are included during the build.

!!! example "ContainerFile used for the build"

    ``` docker
    --8<-- "ContainerFiles/apache"
    ```

## Dependencies

- Used by [Keystone](keystone.md)
