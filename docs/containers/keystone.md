# Keystone

The `keystone` image is built from [ContainerFiles/keystone](https://github.com/rackerlabs/genestack-images/blob/main/ContainerFiles/keystone). Security patches are applied by [scripts/keystone-cve-patching.sh](https://github.com/rackerlabs/genestack-images/blob/main/scripts/keystone-cve-patching.sh).

!!! example "ContainerFile used for the build"

    ``` docker
    --8<-- "ContainerFiles/keystone"
    ```

## Dependencies

- Based on [Apache](apache.md)
