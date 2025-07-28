# Kubernetes Entrypoint

The `kubernetes-entrypoint` image is built from [ContainerFiles/kubernetes-entrypoint](https://github.com/rackerlabs/genestack-images/blob/main/ContainerFiles/kubernetes-entrypoint). Security patches are applied by [scripts/kubernetes-entrypoint-cve-patching.sh](https://github.com/rackerlabs/genestack-images/blob/main/scripts/kubernetes-entrypoint-cve-patching.sh).

!!! example "ContainerFile used for the build"

    ``` docker
    --8<-- "ContainerFiles/kubernetes-entrypoint"
    ```
