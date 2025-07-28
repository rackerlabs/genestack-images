# Kubernetes Entrypoint

The `kubernetes-entrypoint` image is built from [ContainerFiles/kubernetes-entrypoint](https://github.com/rackerlabs/genestack-images/blob/main/ContainerFiles/kubernetes-entrypoint). Security patches are applied by [scripts/kubernetes-entrypoint-cve-patching.sh](https://github.com/rackerlabs/genestack-images/blob/main/scripts/kubernetes-entrypoint-cve-patching.sh).

This container packages the Kubernetes Entrypoint service for use in the stack. The build installs the required packages, applies security updates and configuration, and prepares the service for integration.

``` mermaid
graph LR
    A[Base image] --> B[Install packages]
    B --> C[Apply CVE patches]
    C --> D[Configure Kubernetes Entrypoint]
    D --> E[Container ready]
```

??? example "ContainerFile used for the build"

    ``` docker
    --8<-- "ContainerFiles/kubernetes-entrypoint"
    ```

## Dependencies

- Builds From [OpenStack Virtual Environment](openstack-venv.md)
