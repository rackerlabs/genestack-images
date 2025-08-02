#!/usr/bin/env bash

if [ ${KUBE_OVN_VERSION:-master} = "v1.14.4" ]; then
    # CVE fixes CVE-2025-54388,CVE-2025-22870,CVE-2025-22872,CVE-2025-22868
    go get -u github.com/docker/docker
    go get -u golang.org/x/net
    go get -u golang.org/x/oauth2
elif [ ${KUBE_OVN_VERSION:-master} = "v1.13.14" ]; then
    # CVE fixes CVE-2025-22870,CVE-2025-22872,CVE-2025-22868
    go get -u golang.org/x/net
    go get -u golang.org/x/oauth2
fi
