# utils/colors.py
from colorama import Fore, Back, Style, init
init(autoreset=True)

class Colors:
    RED     = Fore.RED + Style.BRIGHT
    GREEN   = Fore.GREEN + Style.BRIGHT
    YELLOW  = Fore.YELLOW + Style.BRIGHT
    CYAN    = Fore.CYAN + Style.BRIGHT
    BLUE    = Fore.BLUE + Style.BRIGHT
    MAGENTA = Fore.MAGENTA + Style.BRIGHT
    WHITE   = Fore.WHITE + Style.BRIGHT
    RESET   = Style.RESET_ALL
    BOLD    = Style.BRIGHT
    DIM     = Style.DIM

def success(msg): print(f'{Colors.GREEN}[+] {msg}{Colors.RESET}')
def error(msg):   print(f'{Colors.RED}[-] {msg}{Colors.RESET}')
def info(msg):    print(f'{Colors.CYAN}[*] {msg}{Colors.RESET}')
def warn(msg):    print(f'{Colors.YELLOW}[!] {msg}{Colors.RESET}')
