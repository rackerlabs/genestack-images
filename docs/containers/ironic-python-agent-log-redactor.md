# Ironic Python Agent Log Redactor

The `ipa-log-redactor` image is built from [ContainerFiles/ipa-log-redactor](https://github.com/rackerlabs/genestack-images/blob/main/ContainerFiles/ipa-log-redactor). Security patches are applied by [scripts/ironic-cve-patching.sh](https://github.com/rackerlabs/genestack-images/blob/main/scripts/ironic-cve-patching.sh).

This container packages the Ironic Python Agent Log Redactor to redact diagnostic logs and stream them to standard output. The build installs the required packages, applies security updates and configuration, and prepares the service for integration.

``` mermaid
graph LR
    A[Base image] --> B[Install packages]
    B --> C[Apply CVE patches]
    C --> D[Configure Ironic Python Agent Log Redactor]
    D --> E[Container ready]
```

??? example "ContainerFile used for the build"

    ``` docker
    --8<-- "ContainerFiles/ipa-log-redactor"
    ```

## Build Arguments

| Argument | Default |
| --- | --- |
| VENV_TAG | 3.12-latest |
| CACHEBUST | 0 |

??? example "Build Command"

    ``` bash
    docker build \
    --build-arg VENV_TAG=3.12-latest \
    --build-arg CACHEBUST=0 \
    -f ContainerFiles/ipa-log-redactor \
    -t ipa-log-redactor:local \
    .
    ```

## Dependencies

- Builds From [OpenStack Virtual Environment](openstack-venv.md)

## Container Image

The container image is available on [Github Container Registry](https://github.com/rackerlabs/genestack-images/pkgs/container/genestack-images%2Fipa-log-redactor).
