# Faraday - Open Source Vulnerability Manager

![logo](./docs/images/faraday_logo.svg)

[![Twitter Followers](https://img.shields.io/twitter/follow/faradaysec)](https://twitter.com/faradaysec)
[![Docker Pulls](https://img.shields.io/docker/pulls/faradaysec/faraday)](https://hub.docker.com/r/faradaysec/faraday)

## Overview

Faraday is a centralized vulnerability management solution that streamlines vulnerability discovery and remediation efforts. It helps security teams by:

- Aggregating and normalizing data from multiple security tools and scanners
- Providing visualizations and analytics to track security posture
- Supporting multiuser collaboration and workflow management
- Enabling automation through integrations and a rich API

## Key Features

- **Vulnerability Management:** Track, normalize and analyze vulnerability data from 80+ security tools
- **Multiuser Platform:** Collaborate with team members in real-time
- **Plugin Architecture:** Easily integrate new security tools and data sources
- **REST API:** Automate workflows and integrate with other systems
- **CI/CD Integration:** Include security scanning in development pipelines
- **Visualization:** Interactive dashboards to track security metrics
- **Command Line Interface:** Direct terminal access to core functionality

## Quick Start 

### Docker Compose

The easiest way to get started is using Docker Compose:

```bash
$ wget https://raw.githubusercontent.com/infobyte/faraday/master/docker-compose.yaml
$ docker-compose up
```

For customization options, see the [Docker installation guide](https://docs.faradaysec.com/Install-guide-Docker/).

### Docker

Make sure you have [PostgreSQL](https://github.com/infobyte/faraday/wiki/Install-Guide) running first:

```bash
$ docker run \
    -v $HOME/.faraday:/home/faraday/.faraday \
    -p 5985:5985 \
    -e PGSQL_USER='postgres_user' \
    -e PGSQL_HOST='postgres_ip' \
    -e PGSQL_PASSWD='postgres_password' \
    -e PGSQL_DBNAME='postgres_db_name' \
    faradaysec/faraday:latest
```

### PyPI Installation

```bash
$ pip3 install faradaysec
$ faraday-manage initdb
$ faraday-server
```

### Binary Packages

You can find installers on the [releases page](https://github.com/infobyte/faraday/releases):

```bash
$ sudo apt install faraday-server_amd64.deb
# Add your user to the faraday group
$ faraday-manage initdb
$ sudo systemctl start faraday-server
```

### Source Installation

For development from source:

```bash
$ pip3 install virtualenv
$ virtualenv faraday_venv
$ source faraday_venv/bin/activate
$ git clone git@github.com:infobyte/faraday.git
$ pip3 install .
$ faraday-manage initdb
$ faraday-server
```

Access the web interface at http://localhost:5985 and login with username "faraday" and the password provided during installation.

## Usage Documentation

### Integrating with CI/CD Pipelines

Setup security scanning in common CI/CD platforms:

- [GitHub Actions](https://faradaysec.com/wp-content/whitepapers/Integrating%20Faraday%20-%20Part%20One.pdf)
- [Jenkins](https://faradaysec.com/wp-content/whitepapers/Integrating%20Faraday%20-%20Part%20Two.pdf) 
- [TravisCI](https://faradaysec.com/wp-content/whitepapers/Integrating%20Faraday%20-%20Part%20Three.pdf)
- [GitLab](https://faradaysec.com/wp-content/whitepapers/Integrating%20Faraday%20-%20Part%20Four.pdf)

### Command Line Interface

Faraday CLI provides direct terminal access for:

- Running security scans
- Integrating with CI/CD pipelines 
- Generating metrics and reports

Install:
```bash
$ pip3 install faraday-cli
```

Documentation: [Faraday CLI Docs](https://docs.faraday-cli.faradaysec.com/)

### Faraday Agents

[Faraday Agents](https://github.com/infobyte/faraday_agent_dispatcher) enable:

- Remote scanning and data collection
- Custom tool integrations
- Automated vulnerability discovery

### Supported Tools 

Connect your security tools through [plugins](https://github.com/infobyte/faraday_plugins). Currently supports 80+ tools including Nmap, Burp Suite, OWASP ZAP and more.

Missing a tool? [Create a PR](https://github.com/infobyte/faraday_plugins/issues)!

## API Documentation

Access API documentation at: [api.faradaysec.com](https://api.faradaysec.com)

## Links

- Homepage: [faradaysec.com](https://faradaysec.com)
- Docs: [docs.faradaysec.com](https://docs.faradaysec.com)
- Downloads: [Releases](https://github.com/infobyte/faraday/releases) 
- Support: [GitHub Issues](https://github.com/infobyte/faraday/issues)
- FAQ: [Documentation FAQ](https://docs.faradaysec.com/FAQ/)
- Twitter: [@faradaysec](https://twitter.com/faradaysec)
- Demo: [Live Demo](https://demo101.faradaysec.com/#/login)
