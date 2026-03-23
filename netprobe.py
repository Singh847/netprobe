#!/usr/bin/env python3
# netprobe.py — Main entry point

import argparse
import sys
import os

from utils.colors import Colors, info, error, warn

BANNER = f"""
{Colors.CYAN}
  ███╗   ██╗███████╗████████╗██████╗ ██████╗  ██████╗ ██████╗ ███████╗
  ████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██╔══██╗██╔═══██╗██╔══██╗██╔════╝
  ██╔██╗ ██║█████╗     ██║   ██████╔╝██████╔╝██║   ██║██████╔╝█████╗
  ██║╚██╗██║██╔══╝     ██║   ██╔═══╝ ██╔══██╗██║   ██║██╔══██╗██╔══╝
  ██║ ╚████║███████╗   ██║   ██║     ██║  ██║╚██████╔╝██████╔╝███████╗
  ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝
{Colors.RESET}
  {Colors.BOLD}Network & Web Scanner  v2.0{Colors.RESET}
  {Colors.YELLOW}For authorized and educational use only{Colors.RESET}
"""


def parse_args():
    parser = argparse.ArgumentParser(
        prog='netprobe',
        description='NETPROBE — Network & Web Scanner',
        epilog="""
Examples:
  python3 netprobe.py -m host    -t 192.168.1.1
  python3 netprobe.py -m host    -t 192.168.1.1 -p 22 80 443 --save
  sudo python3 netprobe.py -m network -t 192.168.1.0/24 --save
  python3 netprobe.py -m web     -t https://example.com --save
        """
    )
    parser.add_argument('-m', '--mode',
        choices=['host', 'network', 'web'],
        required=True,
        help='Scan mode: host | network | web')
    parser.add_argument('-t', '--target',
        required=True,
        help='IP, hostname, CIDR range, or URL')
    parser.add_argument('-p', '--ports',
        nargs='+', type=int, default=None,
        help='Custom ports for host mode. E.g. -p 22 80 443')
    parser.add_argument('--threads',
        type=int, default=50,
        help='Thread count (default: 50)')
    parser.add_argument('--save',
        action='store_true',
        help='Save JSON report to reports/')
    return parser.parse_args()


def main():
    print(BANNER)
    args = parse_args()

    if args.mode == 'host':
        info(f'Mode: HOST SCAN  |  Target: {args.target}')
        from modules.host_scanner import host_scan
        host_scan(target=args.target, ports=args.ports,
                  threads=args.threads, save=args.save)

    elif args.mode == 'network':
        info(f'Mode: NETWORK SCAN  |  Target: {args.target}')
        if os.geteuid() != 0:
            error('Network scan requires root.')
            error('Run: sudo python3 netprobe.py -m network -t <CIDR>')
            sys.exit(1)
        from modules.network_scanner import network_scan
        network_scan(cidr=args.target, save=args.save)

    elif args.mode == 'web':
        info(f'Mode: WEB SCAN  |  Target: {args.target}')
        from modules.web_scanner import web_scan
        web_scan(url=args.target, save=args.save)


if __name__ == '__main__':
    main()
