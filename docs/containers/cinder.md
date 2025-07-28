# Cinder

The `cinder` image is built from [ContainerFiles/cinder](https://github.com/rackerlabs/genestack-images/blob/main/ContainerFiles/cinder). Security patches are applied by [scripts/cinder-cve-patching.sh](https://github.com/rackerlabs/genestack-images/blob/main/scripts/cinder-cve-patching.sh).

!!! example "ContainerFile used for the build"

    ``` docker
    --8<-- "ContainerFiles/cinder"
    ```

## Dependencies

- Based on [Openstack Venv](openstack-venv.md)
