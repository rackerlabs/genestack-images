# Ceph Libs

The `ceph-libs` image is built from [ContainerFiles/ceph-libs](https://github.com/rackerlabs/genestack-images/blob/main/ContainerFiles/ceph-libs). This image has no dedicated CVE script; security updates are included during the build.

!!! example "ContainerFile used for the build"

    ``` docker
    --8<-- "ContainerFiles/ceph-libs"
    ```

## Dependencies

- Based on [Openstack Venv](openstack-venv.md)
