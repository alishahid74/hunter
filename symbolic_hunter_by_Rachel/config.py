"""
SymbolicHunter Configuration
Central configuration for all modules
"""

import os

# Paths
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
MODULES_DIR = os.path.join(PROJECT_ROOT, 'modules')
TEMPLATES_DIR = os.path.join(PROJECT_ROOT, 'templates')
OUTPUT_DIR = os.path.join(PROJECT_ROOT, 'output')

# Analysis settings
DEFAULT_MAX_STATES = 1000
DEFAULT_TIMEOUT = 300
DEFAULT_STDIN_SIZE = 200

# Dangerous function categories
DANGEROUS_APIS = {
    'memory': ['VirtualAlloc', 'VirtualProtect', 'HeapAlloc', 'malloc', 'calloc', 'realloc'],
    'file': ['CreateFile', 'WriteFile', 'fopen', 'fwrite'],
    'process': ['CreateProcess', 'WinExec', 'ShellExecute', 'system', 'exec', 'popen'],
    'library': ['LoadLibrary', 'GetProcAddress', 'dlopen', 'dlsym'],
    'network': ['connect', 'send', 'recv', 'WSAStartup', 'socket'],
    'string': ['strcpy', 'strcat', 'gets', 'sprintf', 'vsprintf', 'scanf'],
    'format': ['printf', 'fprintf', 'vprintf', 'vfprintf', 'snprintf'],
    'anti_debug': ['IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'NtQueryInformationProcess'],
    'anti_vm': ['cpuid', 'rdtsc'],
    'crypto': ['CryptEncrypt', 'CryptDecrypt', 'BCryptEncrypt']
}

# Taint analysis sinks
TAINT_SINKS = {
    'system': 'Command Injection',
    'exec': 'Command Injection', 
    'popen': 'Command Injection',
    'CreateProcess': 'Command Injection',
    'WinExec': 'Command Injection',
    'ShellExecute': 'Command Injection',
    'strcpy': 'Buffer Overflow',
    'strcat': 'Buffer Overflow',
    'sprintf': 'Buffer Overflow',
    'gets': 'Buffer Overflow',
    'scanf': 'Buffer Overflow',
    'memcpy': 'Buffer Overflow',
    'printf': 'Format String',
    'fprintf': 'Format String',
    'snprintf': 'Format String',
    'LoadLibrary': 'Arbitrary Library Load',
    'dlopen': 'Arbitrary Library Load',
    'fopen': 'Arbitrary File Access',
    'open': 'Arbitrary File Access',
    'CreateFile': 'Arbitrary File Access'
}

# Exploit testing settings
EXPLOIT_TEST_TIMEOUT = 5
EXPLOIT_SANDBOX_ENABLED = True

# Report generation settings
REPORT_INCLUDE_GRAPHS = True
REPORT_INCLUDE_EXPLOITS = True
REPORT_FORMAT = 'html'  # html, pdf, json, all

# Signature generation settings
YARA_ENABLED = True
SNORT_ENABLED = True
SIGMA_ENABLED = True

# Memory analysis settings
SHELLCODE_MIN_SIZE = 20
SHELLCODE_PATTERNS = [
    b'\x90' * 10,  # NOP sled
    b'\xeb\xfe',   # JMP $
    b'\x31\xc0',   # XOR EAX, EAX
]

# Color codes for terminal
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'

# Risk level thresholds
RISK_THRESHOLDS = {
    'CRITICAL': {
        'taint_sinks': 1,
        'anti_analysis': 1,
        'unconstrained': 1,
    },
    'HIGH': {
        'exploit_candidates': 1,
        'total_vulns': 100,
    },
    'MEDIUM': {
        'total_vulns': 10,
    }
}

# Create output directory if it doesn't exist
os.makedirs(OUTPUT_DIR, exist_ok=True)
