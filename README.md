# ThermalDetonatorDetector

Welcome to ThermalDetonatorDetector, an advanced network probing tool designed to detect open DNS resolvers and SNMP servers. Inspired by the strategic intricacies of the Star Wars universe, this project aims to provide network administrators and security professionals with the power to uncover potential vulnerabilities within network infrastructures, akin to detecting thermal detonators before they go off.

## Features

- **DNS Resolver Detection**: Scan various ASNs to identify open DNS resolvers with recursion enabled.
- **SNMP Server Discovery**: Find SNMP servers with known communities and retrieve their system names.
- **Local Caching**: Utilize an SQLite database to cache and quickly retrieve previous scan results, optimizing performance.
- **Configurable Testing**: Customize domain testing lists and success thresholds via a YAML configuration file.
- **YAML Config**: Easily configure your scan parameters, database path, and cache expiry settings through a simple YAML file.

## Prerequisites

Before you set off on your mission, make sure you have the following installed:
- Python 3.x
- Shodan API Key (https://account.shodan.io/) (this may is a **paid** one)
- Shodan library (`shodan`)
- PyYAML (`pyyaml`)
- dnspython (`dnspython`)
- pysnmp (`pysnmp`)

## Installation

Clone the repository to your local machine:

```bash
git clone https://github.com/aweher/ThermalDetonatorDetector.git
cd ThermalDetonatorDetector
```

### Create virtual environment

```bash
python3 -m venv .venv
source ./venv/bin/activate
```

### Install the required Python packages:

```bash
pip install -r requirements.txt
```

## Configuration

All configurations are handled via the `config.yaml` file. Edit it to include your Shodan API key, list of ASNs, SNMP communities, domains to test, and other settings.

```bash
cp config.yaml.example config.yaml
vim config.yaml
```

## Usage

To start a scan with ThermalDetonatorDetector, run:

```bash
python app.py
```

Results will be displayed in the console and stored in the cache for quick future reference.

## Contributing

Contributions to the ThermalDetonatorDetector are welcome. Whether it's bug reports, feature requests, or code contributions, feel free to make your mark. Please submit pull requests to us.

## License

ThermalDetonatorDetector is released under the [GNU GENERAL PUBLIC LICENSE Version 3](LICENSE).

## May the Force be with Your Network!