#!/usr/bin/env python3
# app.py — Flask web interface for NETPROBE

from flask import Flask, render_template, request, jsonify
import socket, subprocess, concurrent.futures, ssl, json
from datetime import datetime
import urllib3, requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import threading

urllib3.disable_warnings()

app = Flask(__name__)

# ── Shared port list ──────────────────────────────────────────────────────────
COMMON_PORTS = {
    21:'FTP', 22:'SSH', 23:'Telnet', 25:'SMTP', 53:'DNS',
    80:'HTTP', 110:'POP3', 143:'IMAP', 443:'HTTPS', 445:'SMB',
    3306:'MySQL', 3389:'RDP', 5432:'PostgreSQL', 5900:'VNC',
    6379:'Redis', 8080:'HTTP-Alt', 8443:'HTTPS-Alt', 27017:'MongoDB',
}

# ── Host scan logic ───────────────────────────────────────────────────────────
def ping_host(ip):
    try:
        r = subprocess.run(['ping','-c','1','-W','1',ip],
                           capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            for line in r.stdout.split('\n'):
                if 'time=' in line:
                    return True, float(line.split('time=')[1].split()[0])
            return True, 0.0
        return False, None
    except: return False, None

def get_ttl(ip):
    try:
        r = subprocess.run(['ping','-c','1','-W','1',ip],
                           capture_output=True, text=True, timeout=5)
        for line in r.stdout.split('\n'):
            if 'ttl=' in line.lower():
                return int(line.lower().split('ttl=')[1].split()[0])
    except: pass
    return None

def estimate_os(ttl):
    if ttl is None: return 'Unknown'
    if ttl <= 64:   return 'Linux / Unix / Android'
    if ttl <= 128:  return 'Windows'
    return 'Network Device'

def scan_port(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        result = s.connect_ex((ip, port))
        s.close()
        status = 'open' if result == 0 else 'closed'
        return {'port': port, 'service': COMMON_PORTS.get(port,'Unknown'), 'status': status}
    except:
        return {'port': port, 'service': COMMON_PORTS.get(port,'Unknown'), 'status': 'error'}

def do_host_scan(target):
    try:
        ip = socket.gethostbyname(target)
    except: return {'error': f'Cannot resolve {target}'}
    alive, ping_ms = ping_host(ip)
    ttl = get_ttl(ip)
    try: hostname = socket.getfqdn(ip)
    except: hostname = 'N/A'
    ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        futures = [ex.submit(scan_port, ip, p) for p in COMMON_PORTS]
        for f in concurrent.futures.as_completed(futures):
            ports.append(f.result())
    ports.sort(key=lambda x: x['port'])
    now = datetime.now()
    return {
        'target': target, 'ip': ip, 'hostname': hostname,
        'alive': alive, 'ping_ms': ping_ms, 'ttl': ttl,
        'os_guess': estimate_os(ttl),
        'open_ports': len([p for p in ports if p['status']=='open']),
        'ports': ports,
        'date': now.strftime('%Y-%m-%d'),
        'time': now.strftime('%H:%M:%S'),
        'timezone': str(now.astimezone().tzinfo),
    }

# ── Web scan logic ────────────────────────────────────────────────────────────
def do_web_scan(url):
    if not url.startswith('http'): url = 'https://' + url
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path.split('/')[0]
    try: ip = socket.gethostbyname(domain)
    except: ip = 'N/A'
    HEADERS = {'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0'}
    try:
        resp = requests.get(url, headers=HEADERS, timeout=10, verify=False, allow_redirects=True)
    except Exception as e:
        return {'error': str(e)}
    soup = BeautifulSoup(resp.text, 'lxml')
    title = soup.find('title')
    desc  = soup.find('meta', attrs={'name':'description'})
    # SSL
    ssl_info = {}
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5); s.connect((domain, 443))
            cert = s.getpeercert()
        subject = dict(x[0] for x in cert.get('subject',[]))
        issuer  = dict(x[0] for x in cert.get('issuer',[]))
        ssl_info = {'valid':True,'common_name':subject.get('commonName','N/A'),
                    'issuer':issuer.get('organizationName','N/A'),
                    'not_before':cert.get('notBefore','N/A'),
                    'not_after':cert.get('notAfter','N/A')}
    except Exception as e:
        ssl_info = {'valid':False,'error':str(e)}
    # WHOIS
    whois_info = {}
    try:
        import whois
        w = whois.whois(domain)
        whois_info = {
            'registrar': str(w.registrar) if w.registrar else 'N/A',
            'created':   str(w.creation_date) if w.creation_date else 'N/A',
            'expires':   str(w.expiration_date) if w.expiration_date else 'N/A',
            'org':       str(w.org) if w.org else 'N/A',
            'country':   str(w.country) if w.country else 'N/A',
        }
    except: whois_info = {'error': 'WHOIS lookup failed'}
    # Tech detection
    tech = []
    server = resp.headers.get('Server','').lower()
    if 'nginx'   in server: tech.append('Nginx')
    if 'apache'  in server: tech.append('Apache')
    if resp.headers.get('CF-RAY'): tech.append('Cloudflare')
    h = resp.text.lower()
    if 'wp-content' in h: tech.append('WordPress')
    if 'react'      in h: tech.append('React')
    if 'jquery'     in h: tech.append('jQuery')
    if 'bootstrap'  in h: tech.append('Bootstrap')
    if 'angular'    in h: tech.append('Angular')
    # Security headers
    sec = {k: k in resp.headers for k in [
        'Strict-Transport-Security','Content-Security-Policy',
        'X-Frame-Options','X-Content-Type-Options',
        'Referrer-Policy','X-XSS-Protection'
    ]}
    return {
        'url': url, 'final_url': resp.url, 'domain': domain, 'ip': ip,
        'status_code': resp.status_code,
        'response_ms': int(resp.elapsed.total_seconds()*1000),
        'server': resp.headers.get('Server','N/A'),
        'content_type': resp.headers.get('Content-Type','N/A'),
        'title': title.text.strip() if title else 'N/A',
        'description': desc.get('content','N/A') if desc else 'N/A',
        'links': len(soup.find_all('a', href=True)),
        'images': len(soup.find_all('img')),
        'forms': len(soup.find_all('form')),
        'scripts': len(soup.find_all('script', src=True)),
        'technologies': tech,
        'ssl': ssl_info,
        'whois': whois_info,
        'security_headers': sec,
        'redirects': [r.url for r in resp.history],
        'scanned_at': datetime.now().isoformat(),
    }

# ── Routes ────────────────────────────────────────────────────────────────────
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan/host', methods=['POST'])
def host_scan():
    data = request.get_json()
    target = data.get('target','').strip()
    if not target: return jsonify({'error':'No target provided'})
    result = do_host_scan(target)
    return jsonify(result)

@app.route('/scan/web', methods=['POST'])
def web_scan():
    data = request.get_json()
    target = data.get('target','').strip()
    if not target: return jsonify({'error':'No target provided'})
    result = do_web_scan(target)
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)
