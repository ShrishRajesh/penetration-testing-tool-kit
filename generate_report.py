#!/usr/bin/env python3
"""
Report Generator for PenTest Toolkit
This script runs various scans and generates a comprehensive report
"""
import os
import sys
import time
import datetime
from src.port_scanner.scanner import PortScanner
from src.utils.network import (
    is_host_up, get_ip_address, get_hostname, 
    scan_for_common_services, traceroute
)

def generate_header():
    """Generate report header"""
    now = datetime.datetime.now()
    header = f"""
=======================================================================
                    PENETRATION TESTING TOOLKIT REPORT
=======================================================================
Generated: {now.strftime('%Y-%m-%d %H:%M:%S')}

This report contains the results of automated scans performed using
the PenTest Toolkit. The information is provided for educational and
authorized security testing purposes only.

=======================================================================
"""
    return header

def scan_target(target, ports):
    """Scan a target and return results"""
    results = {}
    
    # Resolve hostname if needed
    ip = get_ip_address(target) if not is_valid_ip(target) else target
    hostname = get_hostname(ip) if is_valid_ip(target) else target
    
    results['target'] = target
    results['ip'] = ip
    results['hostname'] = hostname
    
    # Check if host is up
    results['is_up'] = is_host_up(ip) if ip else False
    
    if results['is_up']:
        # Scan ports
        scanner = PortScanner(timeout=1.0)
        port_results = scanner.scan_target(ip, ports)
        results['ports'] = port_results
        
        # Get common services
        results['services'] = scan_for_common_services(ip)
        
        # Get traceroute
        results['traceroute'] = traceroute(ip, max_hops=10)
    
    return results

def is_valid_ip(ip):
    """Check if a string is a valid IP address"""
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    for part in parts:
        try:
            num = int(part)
            if num < 0 or num > 255:
                return False
        except ValueError:
            return False
    return True

def format_port_results(port_results):
    """Format port scan results for the report"""
    if not port_results:
        return "No port scan results available."
    
    output = f"{'PORT':<10} {'STATE':<15} {'SERVICE':<15} {'BANNER'}\n"
    output += "-" * 70 + "\n"
    
    # Filter to show only open ports first
    open_ports = [r for r in port_results if r['state'] in ('open', 'open|filtered')]
    
    if not open_ports:
        return output + "No open ports found."
    
    for result in open_ports:
        banner = result.get('banner', 'None')
        if banner and len(banner) > 30:
            banner = banner[:27] + '...'
        
        output += f"{result['port']:<10} {result['state']:<15} {result['service']:<15} {banner}\n"
    
    return output

def format_traceroute_results(traceroute_results):
    """Format traceroute results for the report"""
    if not traceroute_results:
        return "No traceroute results available."
    
    output = f"{'HOP':<5} {'IP':<20} {'RTT'}\n"
    output += "-" * 40 + "\n"
    
    for hop in traceroute_results:
        ip = hop.get('ip', 'timeout')
        rtt = hop.get('rtt', 'timeout')
        output += f"{hop['hop']:<5} {ip:<20} {rtt}\n"
    
    return output

def format_service_results(service_results):
    """Format service scan results for the report"""
    if not service_results:
        return "No common services detected."
    
    output = f"{'PORT':<10} {'SERVICE'}\n"
    output += "-" * 30 + "\n"
    
    for port, service in sorted(service_results.items()):
        output += f"{port:<10} {service}\n"
    
    return output

def generate_report(targets):
    """Generate a comprehensive report for multiple targets"""
    report = generate_header()
    
    for i, target_info in enumerate(targets):
        target = target_info['target']
        ports = target_info['ports']
        
        report += f"\n\n{'=' * 70}\n"
        report += f"TARGET {i+1}: {target}\n"
        report += f"{'=' * 70}\n\n"
        
        print(f"Scanning {target}...")
        start_time = time.time()
        results = scan_target(target, ports)
        scan_time = time.time() - start_time
        
        # Basic Information
        report += "BASIC INFORMATION\n"
        report += "-" * 20 + "\n"
        report += f"Hostname: {results['hostname']}\n"
        report += f"IP Address: {results['ip']}\n"
        report += f"Status: {'Up' if results['is_up'] else 'Down'}\n"
        report += f"Scan Duration: {scan_time:.2f} seconds\n\n"
        
        if not results['is_up']:
            report += "Host appears to be down or not responding to ping.\n"
            continue
        
        # Port Scan Results
        report += "PORT SCAN RESULTS\n"
        report += "-" * 20 + "\n"
        report += format_port_results(results['ports']) + "\n\n"
        
        # Common Services
        report += "COMMON SERVICES\n"
        report += "-" * 20 + "\n"
        report += format_service_results(results['services']) + "\n\n"
        
        # Traceroute
        report += "TRACEROUTE\n"
        report += "-" * 20 + "\n"
        report += format_traceroute_results(results['traceroute']) + "\n"
    
    # Summary
    report += f"\n\n{'=' * 70}\n"
    report += "SUMMARY\n"
    report += f"{'=' * 70}\n\n"
    report += f"Total targets scanned: {len(targets)}\n"
    report += "This report was generated using the PenTest Toolkit.\n"
    report += "For educational and authorized testing purposes only.\n"
    
    return report

def main():
    """Main function"""
    # Define targets to scan
    targets = [
        {'target': 'example.com', 'ports': [21, 22, 25, 80, 443, 8080]},
        {'target': 'google.com', 'ports': [80, 443, 8080]}
    ]
    
    # Generate the report
    report = generate_report(targets)
    
    # Save the report to a file
    report_file = "pentest_report.txt"
    with open(report_file, "w") as f:
        f.write(report)
    
    print(f"\nReport generated and saved to {report_file}")
    
    # Print the report to console
    print("\n" + report)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nReport generation interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\nError generating report: {str(e)}")
        sys.exit(1)
