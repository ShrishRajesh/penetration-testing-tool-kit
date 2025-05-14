#!/usr/bin/env python3
"""
PenTest Toolkit - Main CLI interface
"""
import sys
import os
import argparse
from typing import List, Dict, Optional, Union

# Import modules
from port_scanner.scanner import PortScanner, PortScannerCLI
from brute_forcer.bruteforcer import BruteForcer, BruteForcerCLI
from utils.network import (
    is_host_up, get_ip_address, get_hostname, is_valid_ip, 
    get_mac_address, traceroute, get_whois_info, scan_for_common_services
)


class PenTestToolkit:
    """
    Main class for the PenTest Toolkit
    """
    
    def __init__(self):
        """Initialize the PenTest Toolkit"""
        self.port_scanner = PortScanner()
        self.brute_forcer = BruteForcer()
        
    def run_port_scan(self, args):
        """Run port scanner module"""
        scanner_cli = PortScannerCLI()
        scanner_cli.scanner.timeout = args.timeout
        scanner_cli.scanner.max_threads = args.threads
        scanner_cli.run(args.target, args.ports, args.type)
        
    def run_brute_force(self, args):
        """Run brute forcer module"""
        brute_cli = BruteForcerCLI()
        brute_cli.brute_forcer.timeout = args.timeout
        brute_cli.brute_forcer.max_threads = args.threads
        
        # Prepare additional arguments for HTTP form brute force
        kwargs = {}
        if args.protocol == 'http_form':
            kwargs = {
                'username_field': args.username_field,
                'password_field': args.password_field,
                'success_text': args.success_text,
                'failure_text': args.failure_text
            }
        
        brute_cli.run(args.protocol, args.target, args.port, args.usernames, args.passwords, **kwargs)
        
    def run_network_utils(self, args):
        """Run network utilities"""
        if args.util == 'ping':
            result = is_host_up(args.target, args.timeout)
            print(f"Host {args.target} is {'up' if result else 'down'}")
            
        elif args.util == 'resolve':
            if is_valid_ip(args.target):
                hostname = get_hostname(args.target)
                print(f"IP {args.target} resolves to: {hostname or 'Not found'}")
            else:
                ip = get_ip_address(args.target)
                print(f"Hostname {args.target} resolves to: {ip or 'Not found'}")
                
        elif args.util == 'mac':
            mac = get_mac_address(args.target)
            print(f"MAC address for {args.target}: {mac or 'Not found'}")
            
        elif args.util == 'traceroute':
            print(f"Traceroute to {args.target}:")
            hops = traceroute(args.target, args.max_hops, args.timeout)
            
            for hop in hops:
                ip = hop.get('ip', 'timeout')
                rtt = hop.get('rtt', 'timeout')
                print(f"{hop['hop']}: {ip} ({rtt})")
                
        elif args.util == 'whois':
            print(f"WHOIS information for {args.target}:")
            info = get_whois_info(args.target)
            
            if 'error' in info:
                print(f"Error: {info['error']}")
            else:
                for key, value in info.items():
                    print(f"{key}: {value}")
                    
        elif args.util == 'services':
            print(f"Scanning for common services on {args.target}:")
            services = scan_for_common_services(args.target, args.timeout)
            
            if services:
                print(f"{'PORT':<10} {'SERVICE'}")
                print("-" * 20)
                
                for port, service in sorted(services.items()):
                    print(f"{port:<10} {service}")
            else:
                print("No common services found")


def main():
    """Main entry point for the PenTest Toolkit"""
    # Create the main parser
    parser = argparse.ArgumentParser(
        description="PenTest Toolkit - A comprehensive penetration testing toolkit",
        epilog="Use '<command> --help' for more information on a specific command"
    )
    subparsers = parser.add_subparsers(dest='command', help='Command to run')
    
    # Port Scanner subparser
    port_parser = subparsers.add_parser('scan', help='Run port scanner')
    port_parser.add_argument("target", help="Target IP, hostname, or network in CIDR notation")
    port_parser.add_argument("ports", help="Ports to scan (e.g., '80,443,8000-8100')")
    port_parser.add_argument("--type", choices=["tcp_connect", "tcp_syn", "udp"], 
                             default="tcp_connect", help="Scan type")
    port_parser.add_argument("--timeout", type=float, default=1.0, 
                             help="Connection timeout in seconds")
    port_parser.add_argument("--threads", type=int, default=100, 
                             help="Maximum number of threads")
    
    # Brute Forcer subparser
    brute_parser = subparsers.add_parser('brute', help='Run brute forcer')
    brute_parser.add_argument("protocol", choices=["ssh", "ftp", "http_basic", "http_form"],
                              help="Protocol to brute force")
    brute_parser.add_argument("target", help="Target IP, hostname, or URL")
    brute_parser.add_argument("--port", type=int, help="Port number (required for SSH/FTP)")
    brute_parser.add_argument("--usernames", required=True, help="Path to file containing usernames")
    brute_parser.add_argument("--passwords", required=True, help="Path to file containing passwords")
    brute_parser.add_argument("--timeout", type=float, default=5.0, 
                              help="Connection timeout in seconds")
    brute_parser.add_argument("--threads", type=int, default=10, 
                              help="Maximum number of threads")
    
    # HTTP form specific arguments
    brute_parser.add_argument("--username-field", help="Username field name for HTTP form")
    brute_parser.add_argument("--password-field", help="Password field name for HTTP form")
    brute_parser.add_argument("--success-text", help="Text that indicates successful login")
    brute_parser.add_argument("--failure-text", help="Text that indicates failed login")
    
    # Network Utilities subparser
    net_parser = subparsers.add_parser('net', help='Run network utilities')
    net_parser.add_argument("util", choices=["ping", "resolve", "mac", "traceroute", "whois", "services"],
                            help="Network utility to run")
    net_parser.add_argument("target", help="Target IP, hostname, or domain")
    net_parser.add_argument("--timeout", type=float, default=1.0, 
                            help="Timeout in seconds")
    net_parser.add_argument("--max-hops", type=int, default=30, 
                            help="Maximum number of hops for traceroute")
    
    # Parse arguments
    args = parser.parse_args()
    
    # Run the appropriate command
    toolkit = PenTestToolkit()
    
    if args.command == 'scan':
        toolkit.run_port_scan(args)
    elif args.command == 'brute':
        # Validate brute force arguments
        if args.protocol in ['ssh', 'ftp'] and not args.port:
            parser.error(f"{args.protocol.upper()} brute force requires --port")
        
        if args.protocol == 'http_form' and not (args.username_field and args.password_field):
            parser.error("HTTP form brute force requires --username-field and --password-field")
            
        toolkit.run_brute_force(args)
    elif args.command == 'net':
        toolkit.run_network_utils(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nOperation interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\nError: {str(e)}")
        sys.exit(1)
