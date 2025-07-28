# Openstack Venv

The `openstack-venv` image is built from [ContainerFiles/openstack-venv](https://github.com/rackerlabs/genestack-images/blob/main/ContainerFiles/openstack-venv). This image has no dedicated CVE script; security updates are included during the build.

This container packages the Openstack Venv service for use in the stack. The build installs the required packages, applies security updates and configuration, and prepares the service for integration.

``` mermaid
graph LR
    A[Base image] --> B[Install packages]
    B --> C[Apply CVE patches]
    C --> D[Configure Openstack Venv]
    D --> E[Container ready]
    E --> Ceph_Libs
```

??? example "ContainerFile used for the build"

    ``` docker
    --8<-- "ContainerFiles/openstack-venv"
    ```

## Dependencies

- Builds From [Upstream Python](https://hub.docker.com/_/python)
