# Openstack Venv

The `openstack-venv` image is built from [ContainerFiles/openstack-venv](https://github.com/rackerlabs/genestack-images/blob/main/ContainerFiles/openstack-venv). This image has no dedicated CVE script; security updates are included during the build.

!!! example "ContainerFile used for the build"

    ``` docker
    --8<-- "ContainerFiles/openstack-venv"
    ```

## Dependencies

- Used by [Ceph Libs](ceph-libs.md), [Cinder](cinder.md)
