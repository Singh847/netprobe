# modules/host_scanner.py
import socket
import subprocess
import concurrent.futures
from utils.colors import success, error, info, warn, Colors
from utils.helpers import resolve_host, get_datetime_info, save_report, print_separator

COMMON_PORTS = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
    53: 'DNS', 80: 'HTTP', 110: 'POP3', 135: 'MS-RPC',
    139: 'NetBIOS', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB',
    993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL', 3306: 'MySQL',
    3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC',
    6379: 'Redis', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt',
    27017: 'MongoDB',
}


def ping_host(ip):
    try:
        cmd = ['ping', '-c', '1', '-W', '1', ip]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if 'time=' in line:
                    ms = float(line.split('time=')[1].split()[0])
                    return True, ms
            return True, 0.0
        return False, None
    except Exception:
        return False, None


def grab_banner(ip, port, timeout=2):
    try:
        s = socket.socket()
        s.settimeout(timeout)
        s.connect((ip, port))
        s.send(b'HEAD / HTTP/1.0\r\n\r\n')
        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
        s.close()
        for line in banner.splitlines():
            line = line.strip()
            if line:
                return line[:80]
        return ''
    except Exception:
        return ''


def scan_port(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        result = s.connect_ex((ip, port))
        s.close()
        if result == 0:
            banner = grab_banner(ip, port)
            return {'port': port, 'service': COMMON_PORTS.get(port, 'Unknown'),
                    'status': 'open', 'banner': banner}
        return {'port': port, 'service': COMMON_PORTS.get(port, 'Unknown'),
                'status': 'closed', 'banner': ''}
    except Exception:
        return {'port': port, 'service': COMMON_PORTS.get(port, 'Unknown'),
                'status': 'error', 'banner': ''}


def get_ttl(ip):
    try:
        cmd = ['ping', '-c', '1', '-W', '1', ip]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        for line in result.stdout.split('\n'):
            if 'ttl=' in line.lower():
                return int(line.lower().split('ttl=')[1].split()[0])
    except Exception:
        pass
    return None


def estimate_os(ttl):
    if ttl is None:
        return 'Unknown'
    if ttl <= 64:
        return 'Linux / Unix / Android'
    if ttl <= 128:
        return 'Windows'
    return 'Network Device (Cisco/Juniper)'


def print_host_report(r):
    dt = r['scan_time']
    print(f'\n{Colors.CYAN}', end='')
    print_separator()
    print('  HOST SCAN RESULTS')
    print_separator()
    print(f'{Colors.RESET}')
    print(f'  {"Target":<14}: {r["target"]}')
    print(f'  {"IP Address":<14}: {r["ip"]}')
    print(f'  {"Hostname":<14}: {r["hostname"]}')
    alive_str = f'{Colors.GREEN}ALIVE{Colors.RESET}' if r['alive'] else f'{Colors.RED}OFFLINE{Colors.RESET}'
    print(f'  {"Status":<14}: {alive_str}')
    if r['ping_ms']:
        print(f'  {"Ping":<14}: {r["ping_ms"]}ms')
    print(f'  {"TTL":<14}: {r["ttl"]}')
    print(f'  {"OS Estimate":<14}: {r["os_guess"]}')
    print(f'  {"Date":<14}: {dt["date"]}')
    print(f'  {"Time":<14}: {dt["time"]}')
    print(f'  {"Timezone":<14}: {dt["timezone"]}')
    print()
    open_ports = [p for p in r['ports'] if p['status'] == 'open']
    print(f'{Colors.CYAN}  PORT SCAN  ({len(open_ports)} open / {len(r["ports"])} scanned){Colors.RESET}')
    print()
    print(f'  {"PORT":<8} {"SERVICE":<14} {"STATUS":<10} BANNER')
    print(f'  {"-" * 58}')
    for p in r['ports']:
        if p['status'] == 'open':
            color = Colors.GREEN
        elif p['status'] == 'closed':
            color = Colors.DIM
        else:
            color = Colors.RED
        banner_short = p['banner'][:40] if p['banner'] else '—'
        print(f'  {color}{p["port"]:<8} {p["service"]:<14} {p["status"]:<10} {banner_short}{Colors.RESET}')
    print()


def host_scan(target, ports=None, threads=50, save=False):
    info(f'Resolving target: {target}')
    ip = resolve_host(target)
    if not ip:
        error('Could not resolve target.')
        return None

    info(f'Target IP: {ip}')
    alive, ping_ms = ping_host(ip)
    if alive:
        success(f'Host is ALIVE  |  Ping: {ping_ms}ms')
    else:
        warn('No ping response — host may be firewalled. Continuing port scan...')

    ttl = get_ttl(ip)
    os_guess = estimate_os(ttl)
    info(f'TTL: {ttl}  |  OS Estimate: {os_guess}')

    try:
        hostname = socket.getfqdn(ip)
    except Exception:
        hostname = 'N/A'

    ports_to_scan = ports if ports else list(COMMON_PORTS.keys())
    info(f'Scanning {len(ports_to_scan)} ports with {threads} threads...')

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(scan_port, ip, p): p for p in ports_to_scan}
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())

    results.sort(key=lambda x: x['port'])
    open_ports = [r for r in results if r['status'] == 'open']
    success(f'Scan complete. {len(open_ports)} open port(s) found.')

    dt = get_datetime_info()
    report = {
        'target': target, 'ip': ip, 'hostname': hostname,
        'alive': alive, 'ping_ms': ping_ms, 'ttl': ttl,
        'os_guess': os_guess, 'open_ports': len(open_ports),
        'total_ports': len(results), 'ports': results,
        'scan_time': dt,
    }

    print_host_report(report)

    if save:
        save_report(report, f'host_{ip}_{dt["timestamp"]}.json')

    return report
