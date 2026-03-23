# modules/network_scanner.py
import socket
import subprocess
import os
import concurrent.futures
from utils.colors import success, error, info, warn, Colors
from utils.helpers import get_datetime_info, save_report, print_separator


def arp_sweep(cidr, timeout=2):
    try:
        from scapy.all import ARP, Ether, srp
    except ImportError:
        error('Scapy not installed. Run: pip install scapy')
        return []
    info(f'Sending ARP broadcast to {cidr} ...')
    arp_request = ARP(pdst=cidr)
    broadcast   = Ether(dst='ff:ff:ff:ff:ff:ff')
    packet      = broadcast / arp_request
    answered, _ = srp(packet, timeout=timeout, verbose=False)
    hosts = []
    for sent, received in answered:
        hosts.append({'ip': received.psrc, 'mac': received.hwsrc})
    return hosts


def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return 'N/A'


def ping_and_ttl(ip):
    try:
        cmd = ['ping', '-c', '1', '-W', '1', ip]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        if result.returncode != 0:
            return False, None, None
        ping_ms = None
        ttl = None
        for line in result.stdout.split('\n'):
            if 'time=' in line:
                ping_ms = float(line.split('time=')[1].split()[0])
            if 'ttl=' in line.lower():
                ttl = int(line.lower().split('ttl=')[1].split()[0])
        return True, ping_ms, ttl
    except Exception:
        return False, None, None


def estimate_os(ttl):
    if ttl is None:
        return 'Unknown'
    if ttl <= 64:
        return 'Linux/Unix'
    if ttl <= 128:
        return 'Windows'
    return 'Network Device'


def enrich_host(host):
    ip = host['ip']
    host['hostname'] = resolve_hostname(ip)
    alive, ping_ms, ttl = ping_and_ttl(ip)
    host['alive']   = alive
    host['ping_ms'] = ping_ms
    host['ttl']     = ttl
    host['os']      = estimate_os(ttl)
    return host


def print_network_report(r):
    dt = r['scan_time']
    alive_hosts = [h for h in r['hosts'] if h.get('alive')]
    print(f'\n{Colors.CYAN}', end='')
    print_separator('=', 75)
    print(f'  NETWORK SCAN RESULTS  |  {r["cidr"]}')
    print_separator('=', 75)
    print(f'{Colors.RESET}')
    print(f'  {"CIDR Range":<16}: {r["cidr"]}')
    print(f'  {"Total Found":<16}: {r["total_hosts"]}')
    print(f'  {"Alive":<16}: {len(alive_hosts)}')
    print(f'  {"Scanned At":<16}: {dt["datetime"]}')
    print(f'  {"Timezone":<16}: {dt["timezone"]}')
    print()
    print(f'{Colors.CYAN}  {"IP ADDRESS":<18} {"MAC ADDRESS":<20} {"HOSTNAME":<28} {"OS":<16} PING{Colors.RESET}')
    print(f'  {"-" * 88}')
    for h in sorted(r['hosts'], key=lambda x: list(map(int, x['ip'].split('.')))):
        color    = Colors.GREEN if h.get('alive') else Colors.DIM
        ping_str = f'{h["ping_ms"]}ms' if h.get('ping_ms') else '—'
        print(f'  {color}{h["ip"]:<18} {h["mac"]:<20} {h["hostname"]:<28} {h["os"]:<16} {ping_str}{Colors.RESET}')
    print()


def network_scan(cidr, save=False):
    if os.geteuid() != 0:
        error('Network scan requires root. Use: sudo python3 netprobe.py ...')
        return None

    info(f'Starting network scan: {cidr}')
    dt = get_datetime_info()

    hosts = arp_sweep(cidr)
    if not hosts:
        warn('No hosts responded to ARP. Check you are on this subnet.')
        return None

    success(f'ARP sweep complete. {len(hosts)} host(s) found.')
    info('Enriching host data (hostname, OS, ping)...')

    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
        hosts = list(executor.map(enrich_host, hosts))

    report = {
        'cidr': cidr,
        'total_hosts': len(hosts),
        'scan_time': dt,
        'hosts': hosts,
    }

    print_network_report(report)

    if save:
        save_report(report, f'network_{cidr.replace("/", "_")}_{dt["timestamp"]}.json')

    return report
