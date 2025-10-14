"""
SymbolicHunter Memory Analysis Module
Analyzes memory dumps for shellcode, injected DLLs, and ROP gadgets
"""

import re
import struct
from collections import defaultdict

class MemoryAnalyzer:
    def __init__(self, binary_path=None, memory_dump=None):
        """
        Initialize memory analyzer
        
        Args:
            binary_path: Path to binary (optional)
            memory_dump: Raw memory dump bytes (optional)
        """
        self.binary_path = binary_path
        self.memory_dump = memory_dump
        
        if binary_path and not memory_dump:
            self.memory_dump = self._read_binary()
        
        self.findings = {
            'shellcode': [],
            'rop_gadgets': [],
            'heap_spray': [],
            'injected_code': [],
            'suspicious_strings': []
        }
    
    def _read_binary(self):
        """Read binary file"""
        try:
            with open(self.binary_path, 'rb') as f:
                return f.read()
        except:
            return b''
    
    def detect_shellcode(self, min_size=20):
        """
        Detect potential shellcode patterns
        
        Args:
            min_size: Minimum size of shellcode to detect
        
        Returns:
            List of potential shellcode locations
        """
        if not self.memory_dump:
            return []
        
        shellcode_patterns = [
            (b'\x90' * 10, 'NOP sled'),  # NOP sled
            (b'\xeb\xfe', 'Infinite loop (JMP $)'),  # JMP $
            (b'\x31\xc0', 'XOR EAX,EAX'),  # Common shellcode start
            (b'\x64\xa1', 'TEB access'),  # TEB/PEB access
            (b'\xcc' * 5, 'INT3 debugging'),  # Debug breakpoints
            (b'\x90\x90\x90\xc3', 'NOP+RET'),  # NOP slide to RET
        ]
        
        shellcode_found = []
        
        for pattern, description in shellcode_patterns:
            offset = 0
            while True:
                offset = self.memory_dump.find(pattern, offset)
                if offset == -1:
                    break
                
                # Extract context around pattern
                context_start = max(0, offset - 50)
                context_end = min(len(self.memory_dump), offset + 100)
                context = self.memory_dump[context_start:context_end]
                
                shellcode_found.append({
                    'offset': hex(offset),
                    'pattern': description,
                    'size': len(pattern),
                    'context': context.hex()[:200],
                    'executable': self._is_executable_code(context)
                })
                
                offset += len(pattern)
        
        # Look for x86 instruction sequences
        x86_patterns = [
            b'\x55\x8b\xec',  # push ebp; mov ebp, esp (function prologue)
            b'\x5d\xc3',      # pop ebp; ret (function epilogue)
            b'\x50\x51\x52',  # push eax; push ecx; push edx
        ]
        
        for pattern in x86_patterns:
            offset = 0
            while True:
                offset = self.memory_dump.find(pattern, offset)
                if offset == -1:
                    break
                
                # Check if surrounded by executable-looking code
                context = self.memory_dump[offset:offset+50]
                if self._is_executable_code(context):
                    shellcode_found.append({
                        'offset': hex(offset),
                        'pattern': 'x86 instruction sequence',
                        'size': len(pattern),
                        'context': context.hex()[:200],
                        'executable': True
                    })
                
                offset += 1
        
        self.findings['shellcode'] = shellcode_found
        return shellcode_found
    
    def find_rop_gadgets(self, max_gadgets=100):
        """
        Find ROP gadgets in memory
        
        Args:
            max_gadgets: Maximum number of gadgets to find
        
        Returns:
            List of ROP gadgets
        """
        if not self.memory_dump:
            return []
        
        gadgets = []
        
        # Look for RET instructions (0xc3) and nearby code
        offset = 0
        count = 0
        
        while count < max_gadgets:
            offset = self.memory_dump.find(b'\xc3', offset)  # RET
            if offset == -1:
                break
            
            # Get 10 bytes before RET
            start = max(0, offset - 10)
            gadget_bytes = self.memory_dump[start:offset+1]
            
            # Check if it looks like valid code
            if len(gadget_bytes) >= 2:
                gadgets.append({
                    'offset': hex(offset),
                    'bytes': gadget_bytes.hex(),
                    'length': len(gadget_bytes),
                    'ends_with': 'RET'
                })
                count += 1
            
            offset += 1
        
        # Look for other useful gadgets
        useful_instructions = [
            (b'\x58\xc3', 'pop eax; ret'),
            (b'\x59\xc3', 'pop ecx; ret'),
            (b'\x5a\xc3', 'pop edx; ret'),
            (b'\x5b\xc3', 'pop ebx; ret'),
            (b'\x5c\xc3', 'pop esp; ret'),
            (b'\x5d\xc3', 'pop ebp; ret'),
            (b'\x5e\xc3', 'pop esi; ret'),
            (b'\x5f\xc3', 'pop edi; ret'),
        ]
        
        for pattern, description in useful_instructions:
            offset = 0
            while True:
                offset = self.memory_dump.find(pattern, offset)
                if offset == -1:
                    break
                
                gadgets.append({
                    'offset': hex(offset),
                    'bytes': pattern.hex(),
                    'instruction': description,
                    'useful': True
                })
                
                offset += 1
        
        self.findings['rop_gadgets'] = gadgets
        return gadgets
    
    def detect_heap_spray(self):
        """
        Detect heap spray patterns
        
        Returns:
            List of potential heap spray regions
        """
        if not self.memory_dump:
            return []
        
        heap_sprays = []
        
        # Look for repeated patterns (common in heap spraying)
        window_size = 1024
        for i in range(0, len(self.memory_dump) - window_size, window_size):
            chunk = self.memory_dump[i:i+window_size]
            
            # Check for repeated 4-byte patterns
            dwords = [chunk[j:j+4] for j in range(0, len(chunk)-4, 4)]
            if len(dwords) > 0:
                most_common = max(set(dwords), key=dwords.count)
                count = dwords.count(most_common)
                
                # If more than 80% of DWORDs are the same, likely heap spray
                if count > len(dwords) * 0.8:
                    heap_sprays.append({
                        'offset': hex(i),
                        'size': window_size,
                        'pattern': most_common.hex(),
                        'repetitions': count,
                        'percentage': (count / len(dwords)) * 100
                    })
        
        self.findings['heap_spray'] = heap_sprays
        return heap_sprays
    
    def find_suspicious_strings(self):
        """
        Find suspicious strings in memory
        
        Returns:
            List of suspicious strings
        """
        if not self.memory_dump:
            return []
        
        suspicious_patterns = [
            (r'cmd\.exe', 'Command execution'),
            (r'powershell', 'PowerShell execution'),
            (r'http[s]?://[^\s]+', 'URL'),
            (r'\\\\[^\\]+\\[^\\]+', 'UNC path'),
            (r'HKEY_[A-Z_]+', 'Registry key'),
            (r'SeDebugPrivilege', 'Debug privilege'),
            (r'LoadLibrary', 'DLL loading'),
            (r'VirtualAlloc', 'Memory allocation'),
            (r'CreateRemoteThread', 'Thread injection'),
            (r'/bin/sh', 'Shell execution'),
            (r'eval\(', 'Code evaluation'),
        ]
        
        findings = []
        
        # Extract printable strings
        strings = re.findall(b'[\x20-\x7e]{6,}', self.memory_dump)
        
        for string in strings:
            string_str = string.decode('ascii', errors='ignore')
            
            for pattern, description in suspicious_patterns:
                if re.search(pattern, string_str, re.IGNORECASE):
                    findings.append({
                        'string': string_str,
                        'type': description,
                        'offset': hex(self.memory_dump.find(string)),
                        'length': len(string)
                    })
        
        self.findings['suspicious_strings'] = findings
        return findings
    
    def detect_injected_code(self):
        """
        Detect code injection patterns
        
        Returns:
            List of potential injection sites
        """
        injections = []
        
        # Look for common injection signatures
        injection_patterns = [
            (b'MZ', 'PE header (possible DLL injection)'),
            (b'\x4d\x5a\x90\x00', 'Complete PE signature'),
        ]
        
        for pattern, description in injection_patterns:
            offset = 0
            while True:
                offset = self.memory_dump.find(pattern, offset)
                if offset == -1:
                    break
                
                injections.append({
                    'offset': hex(offset),
                    'pattern': description,
                    'bytes': pattern.hex()
                })
                
                offset += 1
        
        self.findings['injected_code'] = injections
        return injections
    
    def _is_executable_code(self, data):
        """
        Heuristic to determine if data looks like executable code
        
        Args:
            data: Bytes to analyze
        
        Returns:
            Boolean indicating if data looks executable
        """
        if len(data) < 10:
            return False
        
        # Check for common x86 opcodes
        common_opcodes = {
            0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,  # PUSH
            0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,  # POP
            0x90,  # NOP
            0xc3,  # RET
            0xe8,  # CALL
            0xe9,  # JMP
            0xeb,  # JMP short
        }
        
        opcode_count = sum(1 for byte in data if byte in common_opcodes)
        return opcode_count > len(data) * 0.3  # >30% common opcodes
    
    def analyze_all(self):
        """
        Run all analysis methods
        
        Returns:
            Complete findings dictionary
        """
        self.detect_shellcode()
        self.find_rop_gadgets()
        self.detect_heap_spray()
        self.find_suspicious_strings()
        self.detect_injected_code()
        
        return self.findings
    
    def generate_report(self):
        """Generate text report of findings"""
        report = f"""
Memory Analysis Report
Generated: {__import__('datetime').datetime.now()}
{'='*60}

SHELLCODE DETECTION:
Found {len(self.findings['shellcode'])} potential shellcode patterns
"""
        
        for sc in self.findings['shellcode'][:5]:
            report += f"\n  - Offset: {sc['offset']}"
            report += f"\n    Pattern: {sc['pattern']}"
            report += f"\n    Executable: {sc['executable']}\n"
        
        report += f"""
ROP GADGETS:
Found {len(self.findings['rop_gadgets'])} ROP gadgets
"""
        
        for gadget in self.findings['rop_gadgets'][:10]:
            if 'instruction' in gadget:
                report += f"\n  - {gadget['offset']}: {gadget['instruction']}"
        
        report += f"""

HEAP SPRAY:
Found {len(self.findings['heap_spray'])} potential heap spray regions
"""
        
        for spray in self.findings['heap_spray']:
            report += f"\n  - Offset: {spray['offset']}, Size: {spray['size']}"
            report += f"\n    Pattern: {spray['pattern']}, Reps: {spray['repetitions']}\n"
        
        report += f"""
SUSPICIOUS STRINGS:
Found {len(self.findings['suspicious_strings'])} suspicious strings
"""
        
        for string in self.findings['suspicious_strings'][:10]:
            report += f"\n  - {string['type']}: {string['string'][:50]}"
        
        return report


def analyze_memory(binary_path=None, memory_dump=None):
    """
    Convenience function to analyze memory
    
    Args:
        binary_path: Path to binary
        memory_dump: Raw memory bytes
    
    Returns:
        Analysis findings
    """
    analyzer = MemoryAnalyzer(binary_path=binary_path, memory_dump=memory_dump)
    return analyzer.analyze_all()
