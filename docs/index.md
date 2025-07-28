---
hide:
  - navigation
  - toc
---

# Genestack Images

![Genestack Logo](assets/images/genestack-fanataguy-part-colored.webp){ align=left : style="max-width:125px" :pointer-events: none; }

Genestack Images are a set of container images used to deploy OpenStack and related services. The images are built from the
Dockerfiles in this repository and are published to the GitHub Container Registry.

Use these pages to learn what containers are available, how CVE patches are applied and where the build files live.

---

<div class="grid cards" markdown>
-   :material-heart:{ .lg } __A Welcoming Community__

    [![Rackspace Cloud Software](assets/images/r-Icon-RGB-Red.svg){ align=left : style="max-width:125px" :pointer-events: none; }](https://discord.gg/2mN5yZvV3a)

    Developing and maintaining Genestack Images in the community for the collective benefit of all users, both individuals and
    organizations alike is a core value of the project. We welcome contributions from anyone who wants to help improve the project,
    whether you are an individual or part of an organization.

    [:octicons-comment-24: Join the Discord](https://discord.gg/2mN5yZvV3a)

- :material-alpha:{ .xl .middle } - __Genestack Images__  __/dʒen.ə.stæk im·age/__

    1. Simplified construction of OpenStack container images.
    2. A set of container images used to deploy OpenStack and related services.
    3. A community of developers and users focused on OpenStack containerization.
    4. A platform for building and sharing OpenStack container images.

</div>

---

## Container Images

The container images in this repository are built using Dockerfiles located in the `ContainerFiles` directory. Each image is
designed to provide a specific OpenStack service or functionality, and they are built with security patches applied through
scripts located in the `scripts` directory.

``` mermaid
graph LR
    A[Base image] --> B[Install packages]
    B --> C[Apply CVE patches]
    C --> D[Configure Service]
    D --> E[Container ready]
```

!!! note "Images follow a similar build process, which includes"

    1. __Base Image__: Starting from a base image, typically an OpenStack virtual environment.
    2. __Install Packages__: Installing the necessary packages for the service.
    3. __Apply CVE Patches__: Applying security patches to ensure the image is secure.
    4. __Configure Service__: Configuring the service to be ready for deployment.
    5. __Container Ready__: Finalizing the image for use in a containerized environment.

All images are built with upstream official images as a base and are designed to be compatible with the OpenStack ecosystem.
