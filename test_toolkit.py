#!/usr/bin/env python3
"""
Test script for the PenTest Toolkit
This script demonstrates basic usage of the toolkit's modules
"""
import os
import sys
from src.port_scanner.scanner import PortScanner
from src.utils.network import is_host_up, get_ip_address

def test_port_scanner():
    """Test the port scanner module"""
    print("\n=== Testing Port Scanner ===")
    
    # Create a port scanner instance
    scanner = PortScanner(timeout=1.0, max_threads=10)
    
    # Target to scan (example.com)
    target = "example.com"
    
    # Resolve hostname to IP
    ip = get_ip_address(target)
    if not ip:
        print(f"Could not resolve {target}")
        return
    
    print(f"Resolved {target} to {ip}")
    
    # Check if host is up
    if not is_host_up(ip):
        print(f"Host {ip} appears to be down")
        return
    
    print(f"Host {ip} is up")
    
    # Scan common web ports
    ports = [80, 443, 8080]
    print(f"Scanning ports {ports} on {ip}...")
    
    results = scanner.scan_target(ip, ports)
    
    # Print results
    print("\nScan Results:")
    print(f"{'PORT':<10} {'STATE':<15} {'SERVICE':<15}")
    print("-" * 40)
    
    for result in results:
        print(f"{result['port']:<10} {result['state']:<15} {result['service']:<15}")

def create_sample_wordlists():
    """Create sample wordlists for testing"""
    # Create a directory for wordlists if it doesn't exist
    os.makedirs("wordlists", exist_ok=True)
    
    # Create a sample username wordlist
    with open("wordlists/usernames.txt", "w") as f:
        f.write("admin\nroot\nuser\ntest\n")
    
    # Create a sample password wordlist
    with open("wordlists/passwords.txt", "w") as f:
        f.write("password\nadmin\n123456\nqwerty\nletmein\n")
    
    print("\n=== Created Sample Wordlists ===")
    print("- wordlists/usernames.txt")
    print("- wordlists/passwords.txt")

def main():
    """Main function"""
    print("PenTest Toolkit Test Script")
    print("==========================")
    
    # Test port scanner
    test_port_scanner()
    
    # Create sample wordlists
    create_sample_wordlists()
    
    print("\n=== Usage Examples ===")
    print("\nPort Scanner Example:")
    print("python src/main.py scan 192.168.1.1 80,443,8000-8100")
    
    print("\nBrute Forcer Example:")
    print("python src/main.py brute ssh 192.168.1.1 --port 22 --usernames wordlists/usernames.txt --passwords wordlists/passwords.txt")
    
    print("\nNetwork Utilities Example:")
    print("python src/main.py net traceroute google.com")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nTest interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\nError: {str(e)}")
        sys.exit(1)
