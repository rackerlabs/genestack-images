# Swift

The `swift` image is built from [ContainerFiles/swift](https://github.com/rackerlabs/genestack-images/blob/main/ContainerFiles/swift).

This container packages OpenStack Swift for use with the openstack-helm `swift` chart. A single image serves every Swift role: proxy, account, container and object servers with their replicators, auditors, updaters, reaper, expirer, reconstructor and sharder, plus `swift-ring-builder` and the `rsync` daemon used for replication. The proxy pipeline middleware (`keystonemiddleware`, `ceilometermiddleware`, and Swift's built-in `s3api`/`s3token`) is included, along with `liberasurecode`/`PyECLib` for erasure-coded storage policies and `xfsprogs` for storage device tooling.

``` mermaid
graph LR
    A[Base image] --> B[Install packages]
    B --> C[Install Swift and middleware]
    C --> D[Configure Swift user and dirs]
    D --> E[Container ready]
```

??? example "ContainerFile used for the build"

    ``` docker
    --8<-- "ContainerFiles/swift"
    ```

## Build Arguments

| Argument | Default |
| --- | --- |
| VENV_TAG | 3.12-latest |
| CACHEBUST | 0 |
| OS_VERSION | master |
| OS_CONSTRAINTS | master |

??? example "Build Command"

    ``` bash
    docker build \
    --build-arg VENV_TAG=3.12-latest \
    --build-arg CACHEBUST=0 \
    --build-arg OS_VERSION=master \
    --build-arg OS_CONSTRAINTS=master \
    -f ContainerFiles/swift \
    -t swift:local \
    .
    ```

## Dependencies

- Builds From [OpenStack Virtual Environment](openstack-venv.md)

## Container Image

The container image is available on [Github Container Registry](https://github.com/rackerlabs/genestack-images/pkgs/container/genestack-images%2Fswift).
