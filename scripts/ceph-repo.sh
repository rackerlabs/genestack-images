#!/usr/bin/env bash

case $CEPH_REPO in
  pve)
    export CEPH_KEY=https://enterprise.proxmox.com/debian/proxmox-release-${OS_RELEASE}.gpg \
           CEPH_SRC="deb [signed-by=/usr/share/keyrings/ceph-keyring.gpg] http://download.proxmox.com/debian/ceph-${CEPH_VERSION} ${OS_RELEASE} no-subscription"

    curl -o /usr/share/keyrings/ceph-keyring.gpg ${CEPH_KEY}
    echo "${CEPH_SRC}" >/etc/apt/sources.list.d/ceph.list

    echo "*** configured repo ***"
    cat /etc/apt/sources.list.d/ceph.list

    echo "*** pin ceph repo and version"
    cat << EOT > /etc/apt/preferences.d/ceph_packages.pref
Package: *
Pin: release o=download.proxmox.com
Pin-Priority: 1001
EOT
  ;;

  *)
    true
  ;;
esac
