# utils/helpers.py
import socket
import datetime
import os
import json
from utils.colors import info, warn


def resolve_host(target):
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        warn(f'Could not resolve hostname: {target}')
        return None


def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        return s.getsockname()[0]
    except Exception:
        return '127.0.0.1'
    finally:
        s.close()


def get_datetime_info():
    now = datetime.datetime.now()
    return {
        'date':      now.strftime('%Y-%m-%d'),
        'time':      now.strftime('%H:%M:%S'),
        'datetime':  now.isoformat(),
        'timezone':  str(datetime.datetime.now().astimezone().tzinfo),
        'timestamp': int(now.timestamp()),
    }


def save_report(data, filename):
    os.makedirs('reports', exist_ok=True)
    path = f'reports/{filename}'
    with open(path, 'w') as f:
        json.dump(data, f, indent=4, default=str)
    info(f'Report saved --> {path}')
    return path


def print_separator(char='=', length=65):
    print(char * length)
