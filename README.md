# PenTest Toolkit

A comprehensive Python-based penetration testing toolkit with multiple modules for port scanning, brute forcing, and network utilities.
*COMPANY*: CODTECH IT SOLUTIONS 
*NAME*: SHRISH RAJESH
*INTERN ID* :CT04DA9798
*DOMAIN*:CYBERSECURITY & ETHICKAL HACKING 
*DURATION*:4 WEEKS
*MENTOR*:NEELA SANTOSH


## Overview

This toolkit provides a collection of tools for security professionals and penetration testers. It includes:

1. **Port Scanner** - Scan for open ports on target systems using various techniques
2. **Brute Forcer** - Perform brute force attacks against various services
3. **Network Utilities** - Perform common network operations and reconnaissance

## Installation

### Prerequisites

- Python 3.6 or higher
- pip (Python package manager)

### Setup

1. Clone or download this repository
2. Install the required dependencies:

```bash
pip install -r requirements.txt
```

## Usage

The toolkit provides a command-line interface with three main commands:

### Port Scanner

Scan for open ports on a target system:

```bash
python src/main.py scan <target> <ports> [options]
```

Arguments:
- `target`: Target IP address, hostname, or network in CIDR notation (e.g., '192.168.1.0/24')
- `ports`: Ports to scan (e.g., '80,443,8000-8100')

Options:
- `--type`: Scan type ('tcp_connect', 'tcp_syn', 'udp'), default: 'tcp_connect'
- `--timeout`: Connection timeout in seconds, default: 1.0
- `--threads`: Maximum number of threads, default: 100

Example:
```bash
python src/main.py scan 192.168.1.1 80,443,8000-8100 --type tcp_connect
```

### Brute Forcer

Perform brute force attacks against various services:

```bash
python src/main.py brute <protocol> <target> [options]
```

Arguments:
- `protocol`: Protocol to brute force ('ssh', 'ftp', 'http_basic', 'http_form')
- `target`: Target IP address, hostname, or URL

Options:
- `--port`: Port number (required for SSH/FTP)
- `--usernames`: Path to file containing usernames (required)
- `--passwords`: Path to file containing passwords (required)
- `--timeout`: Connection timeout in seconds, default: 5.0
- `--threads`: Maximum number of threads, default: 10

HTTP Form specific options:
- `--username-field`: Username field name for HTTP form
- `--password-field`: Password field name for HTTP form
- `--success-text`: Text that indicates successful login
- `--failure-text`: Text that indicates failed login

Example:
```bash
python src/main.py brute ssh 192.168.1.1 --port 22 --usernames usernames.txt --passwords passwords.txt
```

### Network Utilities

Perform common network operations:

```bash
python src/main.py net <util> <target> [options]
```

Arguments:
- `util`: Network utility to run ('ping', 'resolve', 'mac', 'traceroute', 'whois', 'services')
- `target`: Target IP address, hostname, or domain

Options:
- `--timeout`: Timeout in seconds, default: 1.0
- `--max-hops`: Maximum number of hops for traceroute, default: 30

Example:
```bash
python src/main.py net traceroute example.com --max-hops 15
```

## Module Details

### Port Scanner

The port scanner module provides the following features:

- **TCP Connect Scan**: Performs a full TCP connection to detect open ports
- **UDP Scan**: Scans for open UDP ports
- **TCP SYN Scan**: Simulated SYN scan (requires admin/root privileges for actual SYN scan)
- **Banner Grabbing**: Attempts to retrieve service banners from open ports
- **Service Detection**: Identifies common services running on open ports
- **Network Scanning**: Scan entire subnets in CIDR notation

### Brute Forcer

The brute forcer module supports the following protocols:

- **SSH**: Brute force SSH login credentials
- **FTP**: Brute force FTP login credentials
- **HTTP Basic Auth**: Brute force HTTP Basic Authentication
- **HTTP Form**: Brute force web form login pages

Features:
- Multi-threaded brute forcing for faster attacks
- Customizable timeout and thread count
- Support for wordlist files
- Detailed success/failure reporting

### Network Utilities

The network utilities module provides the following tools:

- **Ping**: Check if a host is up
- **Resolve**: Resolve hostnames to IP addresses and vice versa
- **MAC**: Get MAC address for an IP (ARP lookup)
- **Traceroute**: Trace the route to a destination
- **WHOIS**: Get WHOIS information for a domain or IP
- **Services**: Scan for common services on a host

## Security Notice

This toolkit is provided for educational and professional security testing purposes only. Always ensure you have proper authorization before using these tools against any system or network. Unauthorized scanning or attacks may violate laws and regulations.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
