#!/usr/bin/env bash

if [ ${KUBE_OVN_VERSION_ENV:-master} = "v1.14.15" ]; then
    # CVE fixes CVE-2025-54388,CVE-2025-22870,CVE-2025-22872,CVE-2025-22868
    #           CVE-2024-25621
    go get -u github.com/docker/docker
    go get -u golang.org/x/net
    go get -u golang.org/x/oauth2
elif [ ${KUBE_OVN_VERSION_ENV:-master} = "v1.14.10" ]; then
    # CVE fixes CVE-2025-54388,CVE-2025-22870,CVE-2025-22872,CVE-2025-22868
    go get -u github.com/docker/docker
    go get -u golang.org/x/net
    go get -u golang.org/x/oauth2
elif [ ${KUBE_OVN_VERSION_ENV:-master} = "v1.13.14" ]; then
    # CVE fixes CVE-2025-22870,CVE-2025-22872,CVE-2025-22868,GHSA-fv92-fjc5-jj9h
    go get -u github.com/go-viper/mapstructure/v2
    go get -u golang.org/x/net
    go get -u golang.org/x/oauth2
fi
