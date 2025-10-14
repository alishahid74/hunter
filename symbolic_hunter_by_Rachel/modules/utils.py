"""
SymbolicHunter Utilities Module
Shared utility functions used across all modules
"""

import os
import hashlib
import json
from datetime import datetime

class Colors:
    """ANSI color codes for terminal output"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'


def calculate_hashes(file_path):
    """
    Calculate MD5, SHA1, and SHA256 hashes of a file
    
    Args:
        file_path: Path to file
    
    Returns:
        Dictionary with hash values
    """
    hashes = {
        'md5': hashlib.md5(),
        'sha1': hashlib.sha1(),
        'sha256': hashlib.sha256()
    }
    
    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                for h in hashes.values():
                    h.update(chunk)
        
        return {name: h.hexdigest() for name, h in hashes.items()}
    except Exception as e:
        return {'error': str(e)}


def format_bytes(size):
    """
    Format bytes to human-readable size
    
    Args:
        size: Size in bytes
    
    Returns:
        Formatted string
    """
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} TB"


def save_json(data, output_path):
    """
    Save data to JSON file
    
    Args:
        data: Data to save
        output_path: Output file path
    
    Returns:
        Path to saved file
    """
    with open(output_path, 'w') as f:
        json.dump(data, f, indent=2, default=str)
    return output_path


def load_json(file_path):
    """
    Load JSON file
    
    Args:
        file_path: Path to JSON file
    
    Returns:
        Loaded data
    """
    with open(file_path, 'r') as f:
        return json.load(f)


def create_output_directory(base_name='output'):
    """
    Create timestamped output directory
    
    Args:
        base_name: Base directory name
    
    Returns:
        Path to created directory
    """
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    dir_path = os.path.join(base_name, timestamp)
    os.makedirs(dir_path, exist_ok=True)
    return dir_path


def print_banner():
    """Print SymbolicHunter banner"""
    banner = f"""{Colors.BOLD}{Colors.CYAN}
╔═══════════════════════════════════════════════════════════╗
║           SymbolicHunter - Analysis Framework             ║
║       Advanced Binary Analysis & Exploit Generation       ║
╚═══════════════════════════════════════════════════════════╝{Colors.END}
"""
    print(banner)


def print_section(title, color=Colors.CYAN):
    """Print formatted section header"""
    print(f"\n{Colors.BOLD}{color}[*] {title}{Colors.END}")


def print_success(message):
    """Print success message"""
    print(f"{Colors.GREEN}[+] {message}{Colors.END}")


def print_error(message):
    """Print error message"""
    print(f"{Colors.RED}[!] {message}{Colors.END}")


def print_warning(message):
    """Print warning message"""
    print(f"{Colors.YELLOW}[!] {message}{Colors.END}")


def print_info(message):
    """Print info message"""
    print(f"{Colors.CYAN}[*] {message}{Colors.END}")


def hex_dump(data, length=16, offset=0):
    """
    Create hex dump of binary data
    
    Args:
        data: Binary data
        length: Bytes per line
        offset: Starting offset
    
    Returns:
        Formatted hex dump string
    """
    result = []
    for i in range(0, len(data), length):
        chunk = data[i:i+length]
        hex_str = ' '.join(f'{b:02x}' for b in chunk)
        ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        result.append(f'{offset+i:08x}  {hex_str:<{length*3}}  {ascii_str}')
    return '\n'.join(result)


def is_pe_file(file_path):
    """Check if file is a Windows PE"""
    try:
        with open(file_path, 'rb') as f:
            return f.read(2) == b'MZ'
    except:
        return False


def is_elf_file(file_path):
    """Check if file is a Linux ELF"""
    try:
        with open(file_path, 'rb') as f:
            return f.read(4) == b'\x7fELF'
    except:
        return False


def get_file_info(file_path):
    """
    Get basic file information
    
    Args:
        file_path: Path to file
    
    Returns:
        Dictionary with file info
    """
    info = {
        'path': file_path,
        'name': os.path.basename(file_path),
        'size': 0,
        'size_formatted': '0 B',
        'exists': os.path.exists(file_path),
        'type': 'Unknown'
    }
    
    if info['exists']:
        stat = os.stat(file_path)
        info['size'] = stat.st_size
        info['size_formatted'] = format_bytes(stat.st_size)
        info['modified'] = datetime.fromtimestamp(stat.st_mtime).isoformat()
        
        # Determine file type
        if is_pe_file(file_path):
            info['type'] = 'PE (Windows Executable)'
        elif is_elf_file(file_path):
            info['type'] = 'ELF (Linux Executable)'
        
        # Calculate hashes
        info['hashes'] = calculate_hashes(file_path)
    
    return info


def extract_strings(file_path, min_length=4):
    """
    Extract printable strings from file
    
    Args:
        file_path: Path to file
        min_length: Minimum string length
    
    Returns:
        List of strings
    """
    import re
    
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        
        # ASCII strings
        ascii_strings = re.findall(
            bytes(f'[\x20-\x7e]{{{min_length},}}', 'ascii'),
            data
        )
        
        # Unicode strings
        unicode_strings = re.findall(
            bytes(f'(?:[\x20-\x7e]\x00){{{min_length},}}', 'ascii'),
            data
        )
        
        strings = [s.decode('ascii', errors='ignore') for s in ascii_strings]
        strings += [s.decode('utf-16le', errors='ignore') for s in unicode_strings]
        
        return list(set(strings))  # Remove duplicates
    except:
        return []


def assess_risk_level(analysis_results):
    """
    Assess overall risk level from analysis results
    
    Args:
        analysis_results: Dictionary with analysis data
    
    Returns:
        Risk level string and color
    """
    taint_sinks = len(analysis_results.get('taint_analysis', {}).get('tainted_sinks', []))
    anti_analysis = len(analysis_results.get('anti_analysis', []))
    total_vulns = sum(len(v) for v in analysis_results.get('vulnerabilities', {}).values())
    exploit_candidates = len(analysis_results.get('exploit_candidates', []))
    
    if taint_sinks > 0 or anti_analysis > 0:
        return 'CRITICAL', Colors.RED
    elif exploit_candidates > 0 or total_vulns > 100:
        return 'HIGH', Colors.RED
    elif total_vulns > 10:
        return 'MEDIUM', Colors.YELLOW
    else:
        return 'LOW', Colors.GREEN


def generate_summary_stats(analysis_results):
    """
    Generate summary statistics from analysis
    
    Args:
        analysis_results: Analysis results dictionary
    
    Returns:
        Summary statistics dictionary
    """
    stats = analysis_results.get('statistics', {})
    
    return {
        'total_vulnerabilities': sum(len(v) for v in analysis_results.get('vulnerabilities', {}).values()),
        'taint_sinks': len(analysis_results.get('taint_analysis', {}).get('tainted_sinks', [])),
        'exploit_candidates': len(analysis_results.get('exploit_candidates', [])),
        'dangerous_apis': len(analysis_results.get('dangerous_functions', [])),
        'anti_analysis_techniques': len(analysis_results.get('anti_analysis', [])),
        'paths_explored': stats.get('paths_explored', 0),
        'code_coverage': stats.get('code_coverage', 0),
        'analysis_time': stats.get('time_elapsed', 0),
        'functions_discovered': stats.get('functions_discovered', 0),
        'basic_blocks': stats.get('basic_blocks', 0)
    }


def create_progress_bar(current, total, width=50):
    """
    Create ASCII progress bar
    
    Args:
        current: Current progress
        total: Total amount
        width: Width of progress bar
    
    Returns:
        Progress bar string
    """
    if total == 0:
        percent = 100
    else:
        percent = (current / total) * 100
    
    filled = int(width * current / total) if total > 0 else 0
    bar = '█' * filled + '░' * (width - filled)
    
    return f'[{bar}] {percent:.1f}% ({current}/{total})'


def sanitize_filename(filename):
    """
    Sanitize filename for safe file operations
    
    Args:
        filename: Original filename
    
    Returns:
        Sanitized filename
    """
    # Remove or replace dangerous characters
    dangerous_chars = ['/', '\\', ':', '*', '?', '"', '<', '>', '|']
    for char in dangerous_chars:
        filename = filename.replace(char, '_')
    
    return filename


def merge_analysis_results(*results):
    """
    Merge multiple analysis result dictionaries
    
    Args:
        *results: Variable number of result dictionaries
    
    Returns:
        Merged results dictionary
    """
    merged = {
        'vulnerabilities': {},
        'dangerous_functions': [],
        'exploit_candidates': [],
        'taint_analysis': {'tainted_sinks': []},
        'statistics': {}
    }
    
    for result in results:
        # Merge vulnerabilities
        for vuln_type, vulns in result.get('vulnerabilities', {}).items():
            if vuln_type not in merged['vulnerabilities']:
                merged['vulnerabilities'][vuln_type] = []
            merged['vulnerabilities'][vuln_type].extend(vulns)
        
        # Merge other lists
        merged['dangerous_functions'].extend(result.get('dangerous_functions', []))
        merged['exploit_candidates'].extend(result.get('exploit_candidates', []))
        
        taint_sinks = result.get('taint_analysis', {}).get('tainted_sinks', [])
        merged['taint_analysis']['tainted_sinks'].extend(taint_sinks)
    
    # Remove duplicates
    merged['dangerous_functions'] = list({f['address']: f for f in merged['dangerous_functions']}.values())
    
    return merged
