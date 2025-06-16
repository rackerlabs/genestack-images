```
  ██████╗ ███████╗███╗   ██╗███████╗███████╗████████╗ █████╗  ██████╗██╗  ██╗
 ██╔════╝ ██╔════╝████╗  ██║██╔════╝██╔════╝╚══██╔══╝██╔══██╗██╔════╝██║ ██╔╝
 ██║  ███╗█████╗  ██╔██╗ ██║█████╗  ███████╗   ██║   ███████║██║     █████╔╝
 ██║   ██║██╔══╝  ██║╚██╗██║██╔══╝  ╚════██║   ██║   ██╔══██║██║     ██╔═██╗
 ╚██████╔╝███████╗██║ ╚████║███████╗███████║   ██║   ██║  ██║╚██████╗██║  ██╗
  ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
                                    IMAGES
```

# Genestack Images

A collection of OpenStack container images built for enterprise deployment, maintained by Rackspace's OpenStack Team.

## Overview

This repository contains GitHub Actions workflows and Containerfiles for building secure, enterprise-ready OpenStack service containers. The images are automatically built, scanned for vulnerabilities, and published to GitHub Container Registry.

## Supported Services

### OpenStack Services

- **Keystone** - OpenStack Identity Service
- **Glance** - OpenStack Image Service
- **Heat** - OpenStack Orchestration Service
- **Neutron** - OpenStack Orchestration Service

### Supporting Services

- **Shibd** - Shibboleth Service Provider daemon
- **OpenStack Venv** - Base image for OpenStack services with Python 3.12
- **Apache** - Apache HTTP server with mod_wsgi

## Container Images

### Keystone

The Keystone container provides OpenStack's identity service with enterprise features:

**Features:**

- Apache2 with mod_wsgi integration
- Shibboleth authentication support
- Rackspace plugin integration
- CVE patching for security compliance

**Build Arguments:**

- `OS_VERSION` - OpenStack version (default: master)
- `OS_CONSTRAINTS` - OpenStack constraints version
- `RXT_VERSION` - Rackspace plugin version (default: main)
- `MOD_WSGI_VERSION` - Apache mod_wsgi version (default: 5.0.2)

#### Running Keystone

```bash
docker run -d \
  --name keystone \
  -p 5000:5000 \
  -p 35357:35357 \
  -v /etc/keystone:/etc/keystone \
  ghcr.io/rackspace/genestack-images/keystone:master-latest
```

#### Building Keystone

```bash
docker build \
  --build-arg OS_VERSION=master \
  --build-arg OS_CONSTRAINTS=master \
  --build-arg RXT_VERSION=main \
  --build-arg MOD_WSGI_VERSION=5.0.2 \
  -f ContainerFiles/keystone \
  -t keystone:local .
```

### Glance

The Glance container provides OpenStack's image service:

**Features:**

- Multiple storage backend support (Swift, S3, Cinder)
- uWSGI application server
- CVE patching for security compliance

**Build Arguments:**

- `OS_VERSION` - OpenStack version (default: master)
- `OS_CONSTRAINTS` - OpenStack constraints version

#### Running Glance

```bash
docker run -d \
  --name glance \
  -p 9292:9292 \
  -v /etc/glance:/etc/glance \
  ghcr.io/rackspace/genestack-images/glance:master-latest
```

#### Building Glance

```bash
docker build \
  --build-arg OS_VERSION=master \
  --build-arg OS_CONSTRAINTS=master \
  -f ContainerFiles/glance \
  -t glance:local .
```

### Heat

The Heat container provides OpenStack's image service:

**Features:**

- uWSGI application server
- CVE patching for security compliance

**Build Arguments:**

- `OS_VERSION` - OpenStack version (default: master)
- `OS_CONSTRAINTS` - OpenStack constraints version

#### Running Heat

```bash
docker run -d \
  --name heat \
  -p 8004:8004 \
  -p 8000:8000 \
  -p 8778:8778 \
  -v /etc/heat:/etc/heat \
  ghcr.io/rackspace/genestack-images/heat:master-latest
```

#### Building Heat

```bash
docker build \
  --build-arg OS_VERSION=master \
  --build-arg OS_CONSTRAINTS=master \
  -f ContainerFiles/heat \
  -t heat:local .
```

### Neutron

The Neutron container provides OpenStack's image service:

**Features:**

- Built to ensure compatibility with OVN
- uWSGI application server
- CVE patching for security compliance

**Build Arguments:**

- `OS_VERSION` - OpenStack version (default: master)
- `OS_CONSTRAINTS` - OpenStack constraints version

#### Running Neutron

```bash
docker run -d \
  --name neutron \
  -p 9292:9292 \
  -v /etc/neutron:/etc/neutron \
  ghcr.io/rackspace/genestack-images/neutron:master-latest
```

#### Building Neutron

```bash
docker build \
  --build-arg OS_VERSION=master \
  --build-arg OS_CONSTRAINTS=master \
  -f ContainerFiles/neutron \
  -t neutron:local .
```

### Shibd

Lightweight Shibboleth Service Provider container:

**Features:**

- Debian Trixie slim base
- Shibboleth SP utilities
- Minimal footprint for security

#### Running Shibd

```bash
docker run -d \
  --name shibd \
  -p 1600:1600 \
  -v /etc/shibboleth:/etc/shibboleth \
  ghcr.io/rackspace/genestack-images/shibd:latest
```

#### Building Shibd

```bash
docker build \
  -f ContainerFiles/shibd \
  -t shibd:local .
```

### OpenStack Venv

The OpenStack Venv container provides OpenStack's a runtime environment:

**Features:**

- Python 3.12 runtime
- Debian Bookworm base

#### Running OpenStack Venv

```bash
docker run -d \
  --name keystone \
  ghcr.io/rackspace/genestack-images/openstack-venv:master-latest
```

#### Building OpenStack Venv

```bash
docker build \
  -f ContainerFiles/openstack-venv \
  -t keystone:local .
```

### Python Ceph Clients

The OpenStack Venv container provides OpenStack's a runtime environment:

**Features:**

- Python 3.12 runtime
- Debian Bookworm base

#### Running Python Ceph Clients

```bash
docker run -d \
  --name ceph-libs \
  --build-arg CEPH_VERSION=main \
  ghcr.io/rackspace/genestack-images/ceph-libs:master-latest
```

#### Building Python Ceph Clients

```bash
docker build \
  -f ContainerFiles/ceph-libs \
  -t ceph-libs:local .
```

### Apache

The OpenStack Venv container provides OpenStack's a runtime environment:

**Features:**

- Python 3.12 runtime
- Debian Bookworm base

#### Running Apache Clients

```bash
docker run -d \
  --name ceph-libs \
  ghcr.io/rackspace/genestack-images/apache:latest
```

#### Building Apache Clients

```bash
docker build \
  -f ContainerFiles/apache \
  --build-arg MOD_WSGI_VERSION=master \
  -t apache:local .
```

## Automation Workflows

Automated workflows are defined in `.github/workflows/` to build, test, and publish images to GitHub Container Registry (GHCR).

### Build Triggers

All containers are built automatically on

- **Pull Requests** - When relevant files change
- **Weekly Schedule** - Every Sunday at midnight UTC
- **Manual Dispatch** - On-demand builds with custom parameters

### Security Scanning

- **Trivy vulnerability scanning** on all builds
- **CVE patching** for known vulnerabilities
- **Security reports** published to workflow summaries

### Supported OpenStack Versions

- `master` - Development branch
- `stable/2024.1` - Caracal release
- `stable/2025.1` - Dalmatian release

### Triggering Manual Builds

Use GitHub's workflow dispatch feature to trigger builds with custom parameters:

1. Navigate to Actions tab in GitHub
2. Select the desired workflow
3. Click "Run workflow"
4. Specify custom parameters as needed

## Security

### CVE Patching

The build process includes automatic patching for known CVEs

- **Keystone**: Patches applied via `scripts/keystone-cve-patching.sh`
- **Glance**: Patches applied via `scripts/glance-cve-patching.sh`
- **Heat**: Patches applied via `scripts/heat-cve-patching.sh`
- **Neutron**: Patches applied via `scripts/neutron-cve-patching.sh`

### Vulnerability Scanning

All images are scanned with Trivy for

- Critical vulnerabilities
- High severity issues
- Results published to workflow summaries

### Security Best Practices

- Non-root user execution (UID/GID 42424)
- Minimal base images
- Regular security updates
- Dependency constraint management

## Contributing

### Adding New Services

1. Create Containerfile in `ContainerFiles/`
2. Add corresponding CVE patching script in `scripts/`
3. Create GitHub Actions workflow in `.github/workflows/`
4. Follow existing naming conventions

### Workflow Structure

Each service workflow should include

- Build matrix for multiple OpenStack versions
- Vulnerability scanning with Trivy
- Automated publishing to GHCR
- Security report generation

## Tags and Versioning

### Tag Format

- `latest` - Latest build (shibd only)
- `{version}-latest` - Latest build for specific OpenStack version
- `{version}-{timestamp}` - Timestamped builds for reproducibility

## Support

For issues and questions

- Create GitHub issues for bugs or feature requests
- Review existing workflows for implementation examples
- Check security scan results for vulnerability information

## License

This project is maintained by Rackspace's OpenStack Team and follows enterprise security and compliance standards.
