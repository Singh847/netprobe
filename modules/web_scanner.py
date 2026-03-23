# modules/web_scanner.py
import socket
import ssl
import urllib3
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup

from utils.colors import success, error, info, warn, Colors
from utils.helpers import get_datetime_info, save_report, print_separator

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HEADERS = {
    'User-Agent': (
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
        'AppleWebKit/537.36 (KHTML, like Gecko) '
        'Chrome/120.0.0.0 Safari/537.36'
    )
}


def fetch_page(url):
    try:
        return requests.get(url, headers=HEADERS, timeout=10,
                            verify=True, allow_redirects=True)
    except requests.exceptions.SSLError:
        warn('SSL error — retrying without verification...')
        try:
            return requests.get(url, headers=HEADERS, timeout=10,
                                verify=False, allow_redirects=True)
        except Exception as e:
            error(f'Request failed: {e}')
            return None
    except Exception as e:
        error(f'Request failed: {e}')
        return None


def extract_meta(html):
    soup    = BeautifulSoup(html, 'lxml')
    title   = soup.find('title')
    desc    = soup.find('meta', attrs={'name': 'description'})
    kw      = soup.find('meta', attrs={'name': 'keywords'})
    og_t    = soup.find('meta', attrs={'property': 'og:title'})
    favicon = soup.find('link', rel=lambda r: r and any('icon' in x for x in r))
    robots  = soup.find('meta', attrs={'name': 'robots'})
    return {
        'title':         title.text.strip()                       if title   else 'N/A',
        'description':   desc.get('content', 'N/A').strip()       if desc    else 'N/A',
        'keywords':      kw.get('content', 'N/A').strip()         if kw      else 'N/A',
        'og_title':      og_t.get('content', 'N/A')               if og_t    else 'N/A',
        'links_count':   len(soup.find_all('a', href=True)),
        'images_count':  len(soup.find_all('img')),
        'forms_count':   len(soup.find_all('form')),
        'scripts_count': len(soup.find_all('script', src=True)),
        'styles_count':  len(soup.find_all('link', rel=lambda r: r and 'stylesheet' in r)),
        'has_favicon':   favicon is not None,
        'robots_meta':   robots.get('content', 'N/A')             if robots  else 'N/A',
    }


def check_ssl(hostname):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(5)
            s.connect((hostname, 443))
            cert = s.getpeercert()
        subject = dict(x[0] for x in cert.get('subject', []))
        issuer  = dict(x[0] for x in cert.get('issuer', []))
        return {
            'valid':       True,
            'common_name': subject.get('commonName', 'N/A'),
            'issuer_org':  issuer.get('organizationName', 'N/A'),
            'issuer_cn':   issuer.get('commonName', 'N/A'),
            'not_before':  cert.get('notBefore', 'N/A'),
            'not_after':   cert.get('notAfter', 'N/A'),
            'alt_names':   [x[1] for x in cert.get('subjectAltName', [])],
        }
    except Exception as e:
        return {'valid': False, 'error': str(e)}


def whois_lookup(domain):
    try:
        import whois
        w = whois.whois(domain)
        return {
            'registrar':    str(w.registrar)       if w.registrar       else 'N/A',
            'created':      str(w.creation_date)   if w.creation_date   else 'N/A',
            'expires':      str(w.expiration_date) if w.expiration_date else 'N/A',
            'updated':      str(w.updated_date)    if w.updated_date    else 'N/A',
            'name_servers': sorted(set(str(ns).lower() for ns in (w.name_servers or []))),
            'org':          str(w.org)             if w.org             else 'N/A',
            'country':      str(w.country)         if w.country         else 'N/A',
        }
    except Exception as e:
        return {'error': str(e)}


def detect_technologies(headers, html=''):
    tech = []
    server     = headers.get('Server', '').lower()
    powered_by = headers.get('X-Powered-By', '').lower()
    if 'nginx'       in server:     tech.append('Nginx')
    if 'apache'      in server:     tech.append('Apache')
    if 'iis'         in server:     tech.append('IIS')
    if 'php'         in powered_by: tech.append('PHP')
    if 'asp.net'     in powered_by: tech.append('ASP.NET')
    if 'express'     in powered_by: tech.append('Express.js')
    if headers.get('CF-RAY'):       tech.append('Cloudflare')
    if headers.get('x-amz-request-id'): tech.append('AWS')
    if html:
        h = html.lower()
        if 'wp-content'       in h: tech.append('WordPress')
        if 'joomla'           in h: tech.append('Joomla')
        if 'drupal'           in h: tech.append('Drupal')
        if 'react'            in h: tech.append('React')
        if 'angular'          in h: tech.append('Angular')
        if 'vue.js'           in h: tech.append('Vue.js')
        if 'jquery'           in h: tech.append('jQuery')
        if 'bootstrap'        in h: tech.append('Bootstrap')
        if 'shopify'          in h: tech.append('Shopify')
        if 'google-analytics' in h: tech.append('Google Analytics')
    return list(dict.fromkeys(tech))


def analyse_security_headers(headers):
    checks = [
        'Strict-Transport-Security',
        'Content-Security-Policy',
        'X-Frame-Options',
        'X-Content-Type-Options',
        'Referrer-Policy',
        'Permissions-Policy',
        'X-XSS-Protection',
    ]
    return {h: h in headers for h in checks}


def print_web_report(r):
    meta = r['meta']
    ssl  = r['ssl']
    w    = r['whois']
    sec  = r['security_headers']
    dt   = r['scan_time']

    print(f'\n{Colors.CYAN}', end='')
    print_separator('=', 65)
    print('  WEB SCAN RESULTS')
    print_separator('=', 65)
    print(f'{Colors.RESET}')

    print(f'{Colors.BOLD}  [ PAGE INFO ]{Colors.RESET}')
    print(f'  {"Title":<22}: {meta["title"]}')
    print(f'  {"Description":<22}: {meta["description"][:70]}')
    print(f'  {"Keywords":<22}: {meta["keywords"][:60]}')
    print()

    print(f'{Colors.BOLD}  [ NETWORK INFO ]{Colors.RESET}')
    print(f'  {"URL":<22}: {r["final_url"]}')
    print(f'  {"Domain":<22}: {r["domain"]}')
    print(f'  {"IP Address":<22}: {r["ip"]}')
    print(f'  {"Status Code":<22}: {r["status_code"]}')
    print(f'  {"Server":<22}: {r["server"]}')
    print(f'  {"Content-Type":<22}: {r["content_type"]}')
    print(f'  {"Response Time":<22}: {r["response_ms"]}ms')
    if r['redirects']:
        print(f'  {"Redirects":<22}: {" -> ".join(r["redirects"])}')
    print()

    print(f'{Colors.BOLD}  [ TECHNOLOGIES ]{Colors.RESET}')
    techs = ', '.join(r['technologies']) if r['technologies'] else 'None detected'
    print(f'  {techs}')
    print()

    print(f'{Colors.BOLD}  [ SSL CERTIFICATE ]{Colors.RESET}')
    if ssl.get('valid'):
        print(f'  {"Valid":<22}: {Colors.GREEN}YES{Colors.RESET}')
        print(f'  {"Common Name":<22}: {ssl.get("common_name")}')
        print(f'  {"Issuer":<22}: {ssl.get("issuer_org")}')
        print(f'  {"Valid From":<22}: {ssl.get("not_before")}')
        print(f'  {"Valid Until":<22}: {ssl.get("not_after")}')
    else:
        print(f'  {"Valid":<22}: {Colors.RED}NO — {ssl.get("error", "Unknown")}{Colors.RESET}')
    print()

    print(f'{Colors.BOLD}  [ WHOIS / DOMAIN INFO ]{Colors.RESET}')
    if 'error' in w:
        print(f'  WHOIS lookup failed: {w["error"]}')
    else:
        print(f'  {"Registrar":<22}: {w.get("registrar")}')
        print(f'  {"Organization":<22}: {w.get("org")}')
        print(f'  {"Country":<22}: {w.get("country")}')
        print(f'  {"Created":<22}: {w.get("created")}')
        print(f'  {"Expires":<22}: {w.get("expires")}')
        ns = w.get("name_servers", [])
        if ns:
            print(f'  {"Nameservers":<22}: {", ".join(ns[:4])}')
    print()

    print(f'{Colors.BOLD}  [ PAGE STATISTICS ]{Colors.RESET}')
    print(f'  {"Links":<22}: {meta["links_count"]}')
    print(f'  {"Images":<22}: {meta["images_count"]}')
    print(f'  {"Scripts":<22}: {meta["scripts_count"]}')
    print(f'  {"Stylesheets":<22}: {meta["styles_count"]}')
    print(f'  {"Forms":<22}: {meta["forms_count"]}')
    print(f'  {"Favicon":<22}: {"Yes" if meta["has_favicon"] else "No"}')
    print()

    print(f'{Colors.BOLD}  [ HTTP SECURITY HEADERS ]{Colors.RESET}')
    for header, present in sec.items():
        color  = Colors.GREEN if present else Colors.RED
        status = 'PRESENT' if present else 'MISSING'
        print(f'  {color}  [{status:<7}]{Colors.RESET}  {header}')
    print()

    print(f'  {"Scanned At":<22}: {dt["datetime"]}')
    print(f'  {"Timezone":<22}: {dt["timezone"]}')
    print()


def web_scan(url, save=False):
    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'https://' + url

    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path.split('/')[0]
    dt     = get_datetime_info()

    info(f'Target URL : {url}')
    info(f'Domain     : {domain}')

    try:
        ip = socket.gethostbyname(domain)
        info(f'Resolved IP: {ip}')
    except Exception:
        ip = 'N/A'
        warn('Could not resolve domain to IP.')

    info('Fetching page...')
    resp = fetch_page(url)
    if not resp:
        error('Failed to fetch page. Aborting.')
        return None

    success(f'HTTP {resp.status_code} in {int(resp.elapsed.total_seconds()*1000)}ms')

    info('Parsing HTML...')
    meta = extract_meta(resp.text)

    info('Checking SSL certificate...')
    ssl_info = check_ssl(domain)

    info('Running WHOIS lookup...')
    whois_info = whois_lookup(domain)

    info('Detecting technologies...')
    technologies = detect_technologies(dict(resp.headers), resp.text)

    info('Analysing security headers...')
    sec_headers = analyse_security_headers(dict(resp.headers))

    redirects = [r.url for r in resp.history] if resp.history else []

    report = {
        'url': url, 'final_url': resp.url,
        'domain': domain, 'ip': ip,
        'status_code': resp.status_code,
        'response_ms': int(resp.elapsed.total_seconds() * 1000),
        'server': resp.headers.get('Server', 'N/A'),
        'content_type': resp.headers.get('Content-Type', 'N/A'),
        'redirects': redirects,
        'technologies': technologies,
        'all_headers': dict(resp.headers),
        'security_headers': sec_headers,
        'ssl': ssl_info,
        'whois': whois_info,
        'meta': meta,
        'scan_time': dt,
    }

    print_web_report(report)

    if save:
        save_report(report, f'web_{domain.replace(".", "_")}_{dt["timestamp"]}.json')

    return report
