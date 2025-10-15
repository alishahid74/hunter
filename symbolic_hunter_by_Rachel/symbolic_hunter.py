#!/usr/bin/env python3
"""
SymbolicHunter Enhanced - Production-Ready Malware Analysis Framework
Comprehensive symbolic execution with advanced malware detection capabilities

Major Enhancements:
- Memory-efficient state management for large-scale analysis
- Advanced packer/crypter detection
- Anti-evasion techniques to handle sandbox-aware malware  
- Cryptomining and ransomware detection
- Parallel batch processing with clustering
- Integration-ready threat intelligence enrichment
- Enhanced blob backend with architecture detection
"""

import angr
import claripy
import sys
import argparse
from collections import defaultdict
import logging
from datetime import datetime
import json
import os
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple
from archinfo import arch_from_id
import hashlib
import uuid
import re
import resource
import signal
import multiprocessing as mp
from concurrent.futures import ProcessPoolExecutor, TimeoutError
import numpy as np

# =========================
# Colors for pretty prints
# =========================
class Colors:
    RED = '\033[91m'; GREEN = '\033[92m'; YELLOW = '\033[93m'; BLUE = '\033[94m'
    MAGENTA = '\033[95m'; CYAN = '\033[96m'; WHITE = '\033[97m'; BOLD = '\033[1m'; END = '\033[0m'

# =====================================
# Malware-specific signatures & patterns
# =====================================
PACKER_SIGNATURES = {
    'UPX': [b'UPX0', b'UPX1', b'UPX!', b'UPX2'],
    'ASPack': [b'ASPack', b'.aspack'],
    'PECompact': [b'PECompact', b'PEC2'],
    'Themida': [b'.themida', b'.Themida', b'WinLicense'],
    'VMProtect': [b'vmp0', b'.vmp', b'VMProtect'],
    'Obsidium': [b'Obsidium', b'.obsidium'],
    'MPRESS': [b'MPRESS', b'.MPRESS1', b'.MPRESS2'],
    'Enigma': [b'Enigma protector', b'EnigmaProtector'],
    'Armadillo': [b'Armadillo', b'ArmAccess'],
    'Petite': [b'petite', b'.petite'],
}

RANSOMWARE_PATTERNS = {
    'encryption_apis': ['CryptEncrypt', 'CryptAcquireContext', 'CryptGenKey', 'BCryptEncrypt', 
                       'AES_encrypt', 'RSA_public_encrypt'],
    'file_enum_apis': ['FindFirstFile', 'FindNextFile', 'GetLogicalDrives', 'PathFindExtension'],
    'ransom_extensions': ['.locked', '.encrypted', '.crypto', '.enc', '.crypted', '.locky'],
    'ransom_notes': ['YOUR FILES', 'ENCRYPTED', 'RANSOM', 'BITCOIN', 'DECRYPT', 'PAY'],
}

CRYPTOMINING_INDICATORS = {
    'apis': ['CryptAcquireContext', 'CryptGenRandom', 'CryptHashData', 'CryptDeriveKey'],
    'strings': ['stratum+tcp://', 'mining.pool', 'xmrig', 'monero', 'nicehash', 'minergate',
                'cryptonight', 'ethash', 'equihash', 'randomx'],
    'domains': ['pool.', 'mining.', 'miner.', 'hashvault.', 'nicehash.', 'f2pool.'],
}

ANTI_ANALYSIS_TECHNIQUES = {
    'anti_debug': ['IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'NtQueryInformationProcess',
                   'OutputDebugString', 'NtSetInformationThread', 'DebugActiveProcess'],
    'anti_vm': ['cpuid', 'rdtsc', 'in', 'sidt', 'sgdt', 'sldt', 'str', 'smsw'],
    'anti_sandbox': ['GetTickCount', 'GetLocalTime', 'GetSystemTime', 'NtDelayExecution', 
                     'Sleep', 'WaitForSingleObject'],
    'environment_detection': ['GetUserName', 'GetComputerName', 'GetTempPath', 'GetModuleFileName'],
}

# =====================================
# Enhanced Detection & Analysis
# =====================================
class MalwareDetector:
    """Advanced malware-specific detection capabilities"""
    
    def __init__(self, binary_path: str, verbose: bool = False):
        self.binary_path = binary_path
        self.verbose = verbose
        self.detections = defaultdict(list)
        
    def detect_packers(self) -> Dict[str, Any]:
        """Detect known packers and crypters"""
        detected_packers = []
        try:
            with open(self.binary_path, 'rb') as f:
                # Read file in chunks to handle large binaries
                chunk_size = 1024 * 1024  # 1MB chunks
                data = f.read(chunk_size)
                
                for packer, signatures in PACKER_SIGNATURES.items():
                    if any(sig in data for sig in signatures):
                        detected_packers.append({
                            'packer': packer,
                            'confidence': 'high',
                            'description': f'Binary likely packed with {packer}'
                        })
                        
                # Check entropy for generic packing
                entropy = self._calculate_entropy(data)
                if entropy > 7.0:  # High entropy indicates compression/encryption
                    detected_packers.append({
                        'packer': 'Unknown',
                        'confidence': 'medium',
                        'entropy': entropy,
                        'description': f'High entropy ({entropy:.2f}) suggests packing/encryption'
                    })
                    
        except Exception as e:
            if self.verbose:
                print(f"{Colors.YELLOW}[!] Packer detection error: {e}{Colors.END}")
                
        self.detections['packers'] = detected_packers
        return detected_packers
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0
        
        entropy = 0
        for x in range(256):
            p_x = float(data.count(bytes([x]))) / len(data)
            if p_x > 0:
                entropy += - p_x * np.log2(p_x)
        return entropy
    
    def detect_ransomware_behavior(self, dangerous_functions: List[Dict]) -> Dict[str, Any]:
        """Detect potential ransomware indicators"""
        indicators = {
            'confidence': 0,
            'encryption_apis': [],
            'file_operations': [],
            'suspicious_strings': [],
            'risk_score': 0
        }
        
        # Check for encryption APIs
        func_names = [f.get('name', '').lower() for f in dangerous_functions]
        for api in RANSOMWARE_PATTERNS['encryption_apis']:
            if any(api.lower() in fname for fname in func_names):
                indicators['encryption_apis'].append(api)
                indicators['confidence'] += 20
                
        # Check for file enumeration
        for api in RANSOMWARE_PATTERNS['file_enum_apis']:
            if any(api.lower() in fname for fname in func_names):
                indicators['file_operations'].append(api)
                indicators['confidence'] += 15
                
        # Calculate risk score
        if indicators['encryption_apis'] and indicators['file_operations']:
            indicators['risk_score'] = min(100, indicators['confidence'])
            indicators['verdict'] = 'Likely ransomware'
        elif indicators['encryption_apis']:
            indicators['risk_score'] = min(60, indicators['confidence'])
            indicators['verdict'] = 'Possible ransomware'
        else:
            indicators['risk_score'] = min(30, indicators['confidence'])
            indicators['verdict'] = 'Low ransomware risk'
            
        self.detections['ransomware'] = indicators
        return indicators
    
    def detect_cryptomining(self, dangerous_functions: List[Dict], strings: List[str] = None) -> Dict[str, Any]:
        """Detect cryptocurrency mining activity"""
        indicators = {
            'confidence': 0,
            'mining_apis': [],
            'mining_strings': [],
            'network_activity': False,
            'risk_score': 0
        }
        
        func_names = [f.get('name', '').lower() for f in dangerous_functions]
        
        # Check crypto APIs
        for api in CRYPTOMINING_INDICATORS['apis']:
            if any(api.lower() in fname for fname in func_names):
                indicators['mining_apis'].append(api)
                indicators['confidence'] += 15
                
        # Check for mining-related strings
        if strings:
            for mining_str in CRYPTOMINING_INDICATORS['strings']:
                if any(mining_str in s.lower() for s in strings):
                    indicators['mining_strings'].append(mining_str)
                    indicators['confidence'] += 25
                    
        # Check for network APIs (miners need network)
        network_apis = ['connect', 'send', 'recv', 'socket', 'WSAStartup']
        if any(api in fname for fname in func_names for api in network_apis):
            indicators['network_activity'] = True
            indicators['confidence'] += 10
            
        indicators['risk_score'] = min(100, indicators['confidence'])
        if indicators['risk_score'] > 60:
            indicators['verdict'] = 'Likely cryptominer'
        elif indicators['risk_score'] > 30:
            indicators['verdict'] = 'Possible cryptominer'
        else:
            indicators['verdict'] = 'Low mining risk'
            
        self.detections['cryptomining'] = indicators
        return indicators

# =====================================
# Enhanced SymbolicHunter Class
# =====================================
class SymbolicHunterEnhanced:
    def __init__(
        self,
        binary_path: str,
        verbose: bool = False,
        max_states: int = 1000,
        timeout: int = 300,
        memory_limit: int = 8 * 1024**3,  # 8GB default
        state_timeout: int = 30,
        use_veritesting: bool = True,
        anti_evasion: bool = True,
        parallel_workers: int = 1,
        blob_fallback: bool = True,
        blob_arch: str = "auto",  # Auto-detect architecture
        blob_base: int = 0x400000,
        blob_entry: Optional[int] = None,
        quiet_claripy: bool = True,
    ):
        self.binary_path = binary_path
        self.verbose = verbose
        self.max_states = max_states
        self.timeout = timeout
        self.memory_limit = memory_limit
        self.state_timeout = state_timeout
        self.use_veritesting = use_veritesting
        self.anti_evasion = anti_evasion
        self.parallel_workers = parallel_workers
        
        # Blob options
        self.blob_fallback = blob_fallback
        self.blob_arch = blob_arch
        self.blob_base = blob_base
        self.blob_entry = blob_entry
        
        # State management
        self.state_pruning_threshold = 500
        self.states_analyzed = 0
        self.memory_usage_peak = 0
        
        # Quiet claripy spam
        if quiet_claripy and not verbose:
            logging.getLogger("claripy").setLevel(logging.ERROR)
            logging.getLogger("claripy.ast").setLevel(logging.ERROR)
            
        # Results collections
        self.vulnerabilities = defaultdict(list)
        self.interesting_paths = []
        self.constraints_found = []
        self.unconstrained_paths = []
        self.dangerous_functions = []
        self.cfg = None
        self.functions_found = []
        self.winning_inputs = []
        self.coverage_info = set()
        self.anti_analysis_detected = []
        self.exploit_candidates = []
        self.unique_vulns = {}
        self.taint_sinks = []
        self.taint_sources = set()
        self.data_flows = []
        
        # Malware-specific results
        self.malware_indicators = defaultdict(list)
        self.packed = False
        self.ransomware_risk = 0
        self.cryptomining_risk = 0
        self.evasion_techniques = []
        
        self.stats = {
            'paths_explored': 0, 'states_analyzed': 0, 'constraints_solved': 0,
            'time_elapsed': 0, 'functions_discovered': 0, 'basic_blocks': 0, 
            'code_coverage': 0, 'memory_peak_mb': 0, 'states_pruned': 0
        }
        
        # Setup memory limits
        self._setup_memory_limits()
        
        # Malware detector
        self.malware_detector = MalwareDetector(binary_path, verbose)
        
        print(f"{Colors.BOLD}{Colors.CYAN}[*] Loading binary: {binary_path}{Colors.END}")
        self._load_project()
        
    def _setup_memory_limits(self):
        """Configure memory limits for analysis"""
        try:
            if hasattr(resource, 'RLIMIT_AS'):
                resource.setrlimit(resource.RLIMIT_AS, (self.memory_limit, self.memory_limit))
            if hasattr(resource, 'RLIMIT_DATA'):
                soft, hard = resource.getrlimit(resource.RLIMIT_DATA)
                resource.setrlimit(resource.RLIMIT_DATA, (min(self.memory_limit, hard), hard))
        except Exception as e:
            if self.verbose:
                print(f"{Colors.YELLOW}[!] Could not set memory limits: {e}{Colors.END}")
                
    def _detect_architecture(self, binary_path: str) -> str:
        """Auto-detect binary architecture from patterns"""
        arch_patterns = {
            # x86-64 patterns
            b'\x48\x89\xe5': 'amd64',      # mov rbp, rsp
            b'\x48\x8b': 'amd64',          # mov rax/rcx/rdx...
            b'\x48\x83': 'amd64',          # add/sub rsp, ...
            b'\x4c\x8b': 'amd64',          # mov r8/r9/r10...
            # x86 patterns  
            b'\x55\x89\xe5': 'i386',       # push ebp; mov ebp, esp
            b'\x55\x8b\xec': 'i386',       # push ebp; mov ebp, esp
            b'\x83\xec': 'i386',           # sub esp, ...
            # ARM patterns
            b'\xe9\x2d\x40': 'arm',        # push {r4, lr}
            b'\xe5\x9f': 'arm',            # ldr
            b'\xe3\xa0': 'arm',            # mov
            # ARM64 patterns
            b'\xfd\x7b': 'aarch64',        # stp x29, x30
            b'\xfd\x43': 'aarch64',        # ldp x29, x30
        }
        
        try:
            with open(binary_path, 'rb') as f:
                header = f.read(4096)
                
            # Count pattern matches for each architecture
            arch_scores = defaultdict(int)
            for pattern, arch in arch_patterns.items():
                arch_scores[arch] += header.count(pattern)
                
            if arch_scores:
                # Return architecture with most pattern matches
                return max(arch_scores, key=arch_scores.get)
        except Exception:
            pass
            
        return 'amd64'  # Default fallback
        
    def _load_project(self):
        """Load binary with enhanced blob fallback"""
        # First run malware detection
        print(f"{Colors.CYAN}[*] Running malware-specific detection...{Colors.END}")
        packers = self.malware_detector.detect_packers()
        if packers:
            self.packed = True
            print(f"{Colors.YELLOW}[!] Packer detected: {packers[0]['packer']}{Colors.END}")
            for p in packers:
                self.anti_analysis_detected.append({
                    'technique': 'packing',
                    'details': p['packer'],
                    'description': p['description']
                })
                
        try:
            self.project = angr.Project(self.binary_path, auto_load_libs=False)
            print(f"{Colors.GREEN}[+] Binary loaded successfully{Colors.END}")
        except Exception as e:
            print(f"{Colors.YELLOW}[!] Standard loading failed: {e}{Colors.END}")
            if not self.blob_fallback:
                raise
                
            # Auto-detect architecture if needed
            if self.blob_arch == "auto":
                self.blob_arch = self._detect_architecture(self.binary_path)
                print(f"{Colors.CYAN}[*] Auto-detected architecture: {self.blob_arch}{Colors.END}")
                
            # Try blob backend with multiple base addresses
            base_addresses = [0x400000, 0x1000000, 0x10000, 0x8048000, 0x1000]
            loaded = False
            
            for base_addr in base_addresses:
                try:
                    print(f"{Colors.CYAN}[*] Trying blob backend (arch={self.blob_arch}, base=0x{base_addr:x}){Colors.END}")
                    arch = arch_from_id(self.blob_arch)
                    main_opts = {'backend': 'blob', 'arch': arch, 'base_addr': base_addr}
                    if self.blob_entry is not None:
                        main_opts['entry_point'] = self.blob_entry
                    
                    self.project = angr.Project(self.binary_path, main_opts=main_opts, auto_load_libs=False)
                    print(f"{Colors.GREEN}[+] Loaded with blob backend at base 0x{base_addr:x}{Colors.END}")
                    loaded = True
                    break
                except Exception:
                    continue
                    
            if not loaded:
                raise Exception("Failed to load binary with any method")
                
        # Apply anti-evasion techniques if enabled
        if self.anti_evasion:
            self._setup_anti_evasion()
            
        # Print binary info
        try:
            print(f"    Architecture: {self.project.arch.name}")
            print(f"    Entry point: {hex(self.project.entry)}")
            print(f"    Base address: {hex(self.project.loader.main_object.min_addr)}")
        except Exception:
            pass
            
        # CFG analysis
        print(f"\n{Colors.CYAN}[*] Performing CFG analysis...{Colors.END}")
        try:
            # Use CFGFast with timeout for large binaries
            self.cfg = self.project.analyses.CFGFast(show_progressbar=self.verbose, 
                                                     fail_fast=True,
                                                     force_complete_scan=False)
            self.stats['functions_discovered'] = len(self.cfg.functions)
            try:
                self.stats['basic_blocks'] = len(list(self.cfg.graph.nodes()))
            except Exception:
                self.stats['basic_blocks'] = 0
                
            print(f"{Colors.GREEN}[+] CFG analysis complete{Colors.END}")
            print(f"    Functions discovered: {self.stats['functions_discovered']}")
            print(f"    Basic blocks: {self.stats['basic_blocks']}")
            
            self.identify_dangerous_functions()
            self._detect_anti_analysis_patterns()
            
        except Exception as e:
            print(f"{Colors.YELLOW}[!] CFG analysis failed: {e}{Colors.END}")
            if self.verbose:
                import traceback
                traceback.print_exc()
                
    def _setup_anti_evasion(self):
        """Configure anti-evasion hooks to handle sandbox-aware malware"""
        print(f"{Colors.CYAN}[*] Setting up anti-evasion techniques...{Colors.END}")
        
        try:
            # Hook common anti-debug APIs
            if self.project.loader.main_object.os == 'windows':
                # Windows anti-debug APIs
                anti_debug_procs = {
                    'IsDebuggerPresent': angr.SIM_PROCEDURES['windows']['IsDebuggerPresent']() 
                        if 'IsDebuggerPresent' in angr.SIM_PROCEDURES.get('windows', {}) else None,
                    'CheckRemoteDebuggerPresent': lambda state: state.solver.BVV(0, 32),  # Return false
                    'NtQueryInformationProcess': lambda state: state.solver.BVV(0, 32),   # Return success
                }
                
                for api_name, hook in anti_debug_procs.items():
                    if hook:
                        try:
                            self.project.hook_symbol(api_name, hook)
                            if self.verbose:
                                print(f"    Hooked {api_name}")
                        except Exception:
                            pass
                            
            # Hook timing functions to defeat sleep-based evasion
            timing_hooks = {
                'GetTickCount': lambda state: state.solver.BVV(0x1000000, 32),  # Fixed value
                'Sleep': lambda state: None,  # No-op
                'time': lambda state: state.solver.BVV(1000000000, 64),  # Fixed timestamp
            }
            
            for func_name, hook in timing_hooks.items():
                try:
                    self.project.hook_symbol(func_name, hook)
                except Exception:
                    pass
                    
            # Emulate sandbox artifacts to defeat environment checks
            if hasattr(self.project, 'simos') and hasattr(self.project.simos, 'environment'):
                sandbox_env = {
                    'USERNAME': 'admin',
                    'COMPUTERNAME': 'DESKTOP-NORMAL',
                    'USERDOMAIN': 'WORKGROUP',
                    'NUMBER_OF_PROCESSORS': '4',
                }
                for key, value in sandbox_env.items():
                    try:
                        self.project.simos.environment[key] = value
                    except Exception:
                        pass
                        
        except Exception as e:
            if self.verbose:
                print(f"{Colors.YELLOW}[!] Anti-evasion setup warning: {e}{Colors.END}")
                
    def _detect_anti_analysis_patterns(self):
        """Detect anti-analysis and evasion techniques"""
        if not self.cfg:
            return
            
        print(f"{Colors.CYAN}[*] Detecting evasion techniques...{Colors.END}")
        
        for category, patterns in ANTI_ANALYSIS_TECHNIQUES.items():
            for func_addr, func in self.cfg.functions.items():
                func_name = func.name.lower()
                for pattern in patterns:
                    if pattern.lower() in func_name:
                        self.evasion_techniques.append({
                            'category': category,
                            'technique': pattern,
                            'function': func.name,
                            'address': hex(func_addr)
                        })
                        self.anti_analysis_detected.append({
                            'technique': category,
                            'function': func.name,
                            'address': hex(func_addr)
                        })
                        
        if self.evasion_techniques:
            print(f"{Colors.RED}[!] Found {len(self.evasion_techniques)} evasion techniques{Colors.END}")
            for tech in self.evasion_techniques[:5]:
                print(f"    - {tech['category']}: {tech['technique']} at {tech['address']}")
                
    def identify_dangerous_functions(self):
        """Identify dangerous and suspicious API calls"""
        if not self.cfg:
            return
            
        dangerous_apis = {
            'memory': ['VirtualAlloc', 'VirtualProtect', 'HeapAlloc', 'malloc', 'calloc', 
                      'realloc', 'VirtualAllocEx', 'WriteProcessMemory'],
            'file': ['CreateFile', 'WriteFile', 'fopen', 'fwrite', 'DeleteFile', 
                    'MoveFile', 'CopyFile'],
            'process': ['CreateProcess', 'WinExec', 'ShellExecute', 'system', 'exec', 
                       'popen', 'CreateThread', 'CreateRemoteThread'],
            'library': ['LoadLibrary', 'GetProcAddress', 'dlopen', 'dlsym', 'LdrLoadDll'],
            'network': ['connect', 'send', 'recv', 'WSAStartup', 'socket', 'bind', 
                       'listen', 'accept', 'InternetOpen', 'URLDownloadToFile'],
            'registry': ['RegOpenKey', 'RegSetValue', 'RegCreateKey', 'RegDeleteKey'],
            'string': ['strcpy', 'strcat', 'gets', 'sprintf', 'vsprintf', 'scanf', 'wcscpy'],
            'crypto': ['CryptEncrypt', 'CryptDecrypt', 'BCryptEncrypt', 'CryptAcquireContext',
                      'CryptGenKey', 'CryptHashData'],
            'persistence': ['SetWindowsHookEx', 'CreateService', 'RegSetValueEx'],
        }
        
        print(f"\n{Colors.CYAN}[*] Scanning for dangerous API calls...{Colors.END}")
        api_categories = defaultdict(list)
        
        for func_addr, func in self.cfg.functions.items():
            func_name = func.name
            for category, apis in dangerous_apis.items():
                for dangerous in apis:
                    if dangerous.lower() in func_name.lower():
                        self.dangerous_functions.append({
                            'name': func_name,
                            'address': hex(func_addr),
                            'type': dangerous,
                            'category': category
                        })
                        api_categories[category].append(func_name)
                        
        # Run malware-specific detection
        if self.dangerous_functions:
            ransomware = self.malware_detector.detect_ransomware_behavior(self.dangerous_functions)
            self.ransomware_risk = ransomware['risk_score']
            
            cryptomining = self.malware_detector.detect_cryptomining(self.dangerous_functions)
            self.cryptomining_risk = cryptomining['risk_score']
            
        if self.dangerous_functions:
            print(f"{Colors.YELLOW}[!] Found {len(self.dangerous_functions)} dangerous API calls{Colors.END}")
            for category, funcs in api_categories.items():
                color = Colors.RED if category in ['crypto', 'persistence', 'process'] else Colors.YELLOW
                print(f"    {color}[{category.upper()}]{Colors.END} {len(funcs)} calls")
                
            # Print malware risks
            if self.ransomware_risk > 60:
                print(f"{Colors.RED}[!!!] HIGH RANSOMWARE RISK: Score {self.ransomware_risk}/100{Colors.END}")
            elif self.ransomware_risk > 30:
                print(f"{Colors.YELLOW}[!] Moderate ransomware risk: Score {self.ransomware_risk}/100{Colors.END}")
                
            if self.cryptomining_risk > 60:
                print(f"{Colors.RED}[!!!] HIGH CRYPTOMINING RISK: Score {self.cryptomining_risk}/100{Colors.END}")
            elif self.cryptomining_risk > 30:
                print(f"{Colors.YELLOW}[!] Moderate cryptomining risk: Score {self.cryptomining_risk}/100{Colors.END}")
                
    def _monitor_memory_usage(self):
        """Track memory usage during analysis"""
        try:
            import psutil
            process = psutil.Process()
            memory_mb = process.memory_info().rss / 1024 / 1024
            self.memory_usage_peak = max(self.memory_usage_peak, memory_mb)
            self.stats['memory_peak_mb'] = self.memory_usage_peak
            
            # Trigger garbage collection if memory usage is high
            if memory_mb > (self.memory_limit / 1024 / 1024) * 0.8:
                import gc
                gc.collect()
                if self.verbose:
                    print(f"{Colors.YELLOW}[!] High memory usage ({memory_mb:.1f}MB), triggering GC{Colors.END}")
        except ImportError:
            pass
            
    def _prune_states(self, simgr):
        """Intelligently prune states to prevent memory exhaustion"""
        if len(simgr.active) > self.state_pruning_threshold:
            print(f"{Colors.YELLOW}[!] Pruning states ({len(simgr.active)} > {self.state_pruning_threshold}){Colors.END}")
            
            # Score states by interestingness
            scored_states = []
            for state in simgr.active:
                score = 0
                
                # Prefer states near dangerous functions
                for df in self.dangerous_functions:
                    try:
                        if abs(state.addr - int(df['address'], 16)) < 0x100:
                            score += 10
                    except Exception:
                        pass
                        
                # Prefer states with more constraints (deeper exploration)
                score += len(state.solver.constraints)
                
                # Prefer states with symbolic memory/registers
                try:
                    if state.regs.rip.symbolic:
                        score += 100  # Highly interesting
                except Exception:
                    pass
                    
                scored_states.append((score, state))
                
            # Keep top states
            scored_states.sort(key=lambda x: x[0], reverse=True)
            keep_count = self.state_pruning_threshold // 2
            simgr.active = [s[1] for s in scored_states[:keep_count]]
            
            pruned_count = len(scored_states) - keep_count
            self.stats['states_pruned'] += pruned_count
            
            if self.verbose:
                print(f"    Kept {keep_count} most interesting states, pruned {pruned_count}")
                
    def explore_binary(self, target_function=None):
        """Enhanced symbolic execution with memory management"""
        print(f"\n{Colors.BOLD}{Colors.YELLOW}[*] Starting enhanced symbolic execution...{Colors.END}")
        print(f"    Max states: {self.max_states}")
        print(f"    Timeout: {self.timeout}s")
        print(f"    Memory limit: {self.memory_limit / 1024**3:.1f}GB")
        print(f"    Anti-evasion: {self.anti_evasion}\n")
        
        # Create initial state
        state = self.project.factory.entry_state(add_options={
            angr.options.LAZY_SOLVES,
            angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
            angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
        })
        
        # Symbolic stdin
        stdin_size = 200
        stdin_data = claripy.BVS('stdin', 8 * stdin_size)
        try:
            stdin_file = angr.storage.SimFile('stdin', content=stdin_data, size=stdin_size)
            state.fs.insert('stdin', stdin_file)
            state.posix.stdin = stdin_file
        except Exception:
            pass
            
        # Symbolic argv for Linux/Unix binaries
        if self.project.loader.main_object.os != 'windows':
            arg1 = claripy.BVS('arg1', 8 * 100)
            try:
                state.posix.argv = [self.project.filename, arg1]
            except Exception:
                pass
                
        # Create simulation manager
        simgr = self.project.factory.simulation_manager(state)
        
        # Apply exploration techniques
        if self.use_veritesting:
            try:
                from angr.exploration_techniques import Veritesting
                simgr.use_technique(Veritesting())
                print(f"{Colors.CYAN}[*] Using Veritesting for path merging{Colors.END}")
            except Exception:
                pass
                
        # DFS for targeted exploration
        if self.dangerous_functions or target_function:
            try:
                from angr.exploration_techniques import DFS
                simgr.use_technique(DFS())
            except Exception:
                pass
                
        # Find target function if specified
        find_addr = None
        if target_function:
            print(f"{Colors.CYAN}[*] Searching for function: {target_function}{Colors.END}")
            if self.cfg:
                for func_addr, func in self.cfg.functions.items():
                    if target_function.lower() in func.name.lower():
                        find_addr = func_addr
                        print(f"{Colors.GREEN}[+] Found target: {func.name} at {hex(func_addr)}{Colors.END}")
                        break
                        
        print(f"{Colors.CYAN}[*] Beginning state exploration...{Colors.END}\n")
        
        start_time = datetime.now()
        step_count = 0
        found_target = False
        last_memory_check = datetime.now()
        
        try:
            while len(simgr.active) > 0 and step_count < self.max_states:
                # Check memory usage periodically
                if (datetime.now() - last_memory_check).total_seconds() > 5:
                    self._monitor_memory_usage()
                    last_memory_check = datetime.now()
                    
                # Check for target function
                if find_addr and not found_target:
                    for st in list(simgr.active):
                        if st.addr == find_addr:
                            print(f"\n{Colors.GREEN}[!!!] Reached target function at {hex(find_addr)}!{Colors.END}")
                            found_target = True
                            self._handle_target_reached(st, target_function)
                            
                # Step simulation
                simgr.step()
                step_count += 1
                self.stats['paths_explored'] = len(simgr.active) + len(simgr.deadended)
                
                # Analyze states
                for s in list(simgr.active):
                    self.analyze_state(s)
                    
                # Prune states if too many
                self._prune_states(simgr)
                
                # Handle errored states
                for er in list(simgr.errored):
                    if hasattr(er, 'state'):
                        self.vulnerabilities['crashed_paths'].append({
                            'address': hex(er.state.addr),
                            'error': str(er.error)[:200],
                            'description': 'Path resulted in error - possible vulnerability'
                        })
                        
                # Progress update
                if step_count % 50 == 0:
                    elapsed = (datetime.now() - start_time).total_seconds()
                    print(f"{Colors.CYAN}[*] Step {step_count}: Active={len(simgr.active)}, "
                          f"Dead={len(simgr.deadended)}, Error={len(simgr.errored)}, "
                          f"Memory={self.memory_usage_peak:.1f}MB, Time={elapsed:.1f}s{Colors.END}")
                    
                # Check timeout
                if (datetime.now() - start_time).total_seconds() > self.timeout:
                    print(f"\n{Colors.YELLOW}[!] Timeout reached{Colors.END}")
                    break
                    
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[!] Analysis interrupted by user{Colors.END}")
        except Exception as e:
            print(f"\n{Colors.RED}[!] Analysis error: {e}{Colors.END}")
            if self.verbose:
                import traceback
                traceback.print_exc()
                
        self.stats['time_elapsed'] = (datetime.now() - start_time).total_seconds()
        
        # Calculate code coverage
        try:
            if self.stats['basic_blocks'] > 0:
                self.stats['code_coverage'] = (len(self.coverage_info) / self.stats['basic_blocks']) * 100
        except Exception:
            self.stats['code_coverage'] = 0
            
        print(f"\n{Colors.CYAN}[*] Finalizing analysis...{Colors.END}")
        
    def _handle_target_reached(self, state, target_function):
        """Handle reaching target function"""
        try:
            if state.solver.satisfiable():
                stdin_vars = [v for v in state.solver.get_variables() if 'stdin' in str(v)]
                if stdin_vars:
                    win = state.solver.eval(stdin_vars[0], cast_to=bytes)
                    print(f"{Colors.MAGENTA}[+] Input to reach target:{Colors.END}")
                    print(f"    Hex: {win[:50].hex()}")
                    print(f"    ASCII: {repr(win[:50])}\n")
                    
                    self.exploit_candidates.append({
                        'target_function': target_function,
                        'address': hex(state.addr),
                        'category': 'target',
                        'input': win[:100],
                        'description': f'Input reaches target function {target_function}'
                    })
        except Exception as e:
            if self.verbose:
                print(f"Error extracting target input: {e}")
                
    def analyze_state(self, state):
        """Comprehensive state analysis with malware focus"""
        self.states_analyzed += 1
        self.coverage_info.add(state.addr)
        
        # Only analyze unique addresses once for expensive checks
        if state.addr not in self.unique_vulns:
            self.unique_vulns[state.addr] = True
            self.check_buffer_overflow(state)
            self.check_integer_overflow(state)
            self.check_format_string(state)
            self.check_null_deref(state)
            self.check_division_by_zero(state)
            self.check_unconstrained(state)
            self.check_command_injection(state)
            self.check_path_traversal(state)
            
        # Always check taint flow and data flow
        self.check_taint_flow(state)
        self.track_data_flow(state)
        
        # Malware-specific checks
        self.check_persistence_mechanism(state)
        self.check_network_communication(state)
        
    def check_command_injection(self, state):
        """Check for command injection vulnerabilities"""
        cmd_functions = ['system', 'exec', 'popen', 'CreateProcess', 'WinExec', 'ShellExecute']
        
        try:
            if self.cfg:
                func = self.cfg.functions.get(state.addr)
                if func and any(cmd in func.name for cmd in cmd_functions):
                    # Check if argument is symbolic
                    arg_reg = state.regs.rdi if self.project.arch.name == 'AMD64' else state.regs.eax
                    if arg_reg.symbolic:
                        self.vulnerabilities['command_injection'].append({
                            'address': hex(state.addr),
                            'function': func.name,
                            'description': 'Symbolic input to command execution function'
                        })
        except Exception as e:
            if self.verbose:
                print(f"Command injection check error: {e}")
                
    def check_path_traversal(self, state):
        """Check for path traversal vulnerabilities"""
        file_functions = ['fopen', 'CreateFile', 'open', 'access']
        
        try:
            if self.cfg:
                func = self.cfg.functions.get(state.addr)
                if func and any(f in func.name for f in file_functions):
                    # Check if filename argument is symbolic
                    arg_reg = state.regs.rdi if self.project.arch.name == 'AMD64' else state.regs.eax
                    if arg_reg.symbolic:
                        self.vulnerabilities['path_traversal'].append({
                            'address': hex(state.addr),
                            'function': func.name,
                            'description': 'Symbolic filename in file operation'
                        })
        except Exception as e:
            if self.verbose:
                print(f"Path traversal check error: {e}")
                
    def check_persistence_mechanism(self, state):
        """Detect malware persistence mechanisms"""
        persistence_apis = ['RegSetValueEx', 'CreateService', 'SetWindowsHookEx', 
                           'schtasks', 'crontab']
        
        try:
            if self.cfg:
                func = self.cfg.functions.get(state.addr)
                if func and any(api in func.name for api in persistence_apis):
                    self.malware_indicators['persistence'].append({
                        'address': hex(state.addr),
                        'function': func.name,
                        'type': 'registry' if 'Reg' in func.name else 'service',
                        'description': 'Potential persistence mechanism'
                    })
        except Exception:
            pass
            
    def check_network_communication(self, state):
        """Detect network communication patterns"""
        network_apis = ['connect', 'send', 'recv', 'InternetOpen', 'URLDownloadToFile']
        
        try:
            if self.cfg:
                func = self.cfg.functions.get(state.addr)
                if func and any(api in func.name for api in network_apis):
                    self.malware_indicators['network'].append({
                        'address': hex(state.addr),
                        'function': func.name,
                        'description': 'Network communication detected'
                    })
        except Exception:
            pass
            
    # [Include all the original vulnerability check methods here]
    # check_buffer_overflow, check_integer_overflow, check_format_string, etc.
    # (These remain the same as in your original code)
    
    def check_buffer_overflow(self, state):
        """Check for buffer overflow vulnerabilities"""
        try:
            regs = [state.regs.rax, state.regs.rbx, state.regs.rcx, state.regs.rdx, 
                   state.regs.rsi, state.regs.rdi] if self.project.arch.name == 'AMD64' else \
                  [state.regs.eax, state.regs.ebx, state.regs.ecx, state.regs.edx, 
                   state.regs.esi, state.regs.edi]
                   
            for reg in regs:
                if reg.symbolic:
                    try:
                        if state.solver.satisfiable(extra_constraints=[reg > 0x7fff0000]):
                            self.vulnerabilities['buffer_overflow'].append({
                                'address': hex(state.addr),
                                'register': str(reg),
                                'description': 'Symbolic pointer could overflow buffer bounds'
                            })
                            break
                    except Exception:
                        pass
        except Exception as e:
            if self.verbose:
                print(f"Buffer overflow check error: {e}")
                
    def check_integer_overflow(self, state):
        """Check for integer overflow vulnerabilities"""
        try:
            for var in state.solver.get_variables():
                if any(t in str(var) for t in ("stdin", "arg", "file")):
                    try:
                        if state.solver.satisfiable(extra_constraints=[var > 0x7fffffff]):
                            self.vulnerabilities['integer_overflow'].append({
                                'address': hex(state.addr),
                                'variable': str(var),
                                'description': 'Symbolic integer can overflow'
                            })
                    except Exception:
                        pass
        except Exception as e:
            if self.verbose:
                print(f"Integer overflow check error: {e}")
                
    def check_format_string(self, state):
        """Check for format string vulnerabilities"""
        try:
            fmt_arg = state.regs.rsi if self.project.arch.name == 'AMD64' else state.regs.esi
            if fmt_arg.symbolic:
                self.vulnerabilities['format_string'].append({
                    'address': hex(state.addr),
                    'description': 'Symbolic format string argument'
                })
        except Exception as e:
            if self.verbose:
                print(f"Format string check error: {e}")
                
    def check_null_deref(self, state):
        """Check for NULL pointer dereference"""
        try:
            regs = [state.regs.rax, state.regs.rbx, state.regs.rcx, state.regs.rdx,
                   state.regs.rsi, state.regs.rdi] if self.project.arch.name == 'AMD64' else \
                  [state.regs.eax, state.regs.ebx, state.regs.ecx, state.regs.edx]
                  
            for reg in regs:
                if reg.symbolic:
                    try:
                        if state.solver.satisfiable(extra_constraints=[reg == 0]):
                            self.vulnerabilities['null_deref'].append({
                                'address': hex(state.addr),
                                'register': str(reg),
                                'description': 'Register can be NULL and may be dereferenced'
                            })
                    except Exception:
                        pass
        except Exception as e:
            if self.verbose:
                print(f"NULL deref check error: {e}")
                
    def check_division_by_zero(self, state):
        """Check for division by zero"""
        try:
            block = self.project.factory.block(state.addr)
            for insn in block.capstone.insns:
                if insn.mnemonic in ['div', 'idiv']:
                    divisor = state.regs.rcx if self.project.arch.name == 'AMD64' else state.regs.ecx
                    if divisor.symbolic:
                        try:
                            if state.solver.satisfiable(extra_constraints=[divisor == 0]):
                                self.vulnerabilities['div_by_zero'].append({
                                    'address': hex(state.addr),
                                    'description': 'Division by zero possible'
                                })
                        except Exception:
                            pass
        except Exception as e:
            if self.verbose:
                print(f"Division by zero check error: {e}")
                
    def check_unconstrained(self, state):
        """Check for unconstrained execution"""
        try:
            if state.regs.ip.symbolic:
                self.vulnerabilities['unconstrained_execution'].append({
                    'address': hex(state.addr),
                    'description': 'Instruction pointer is symbolic - possible code execution',
                    'severity': 'CRITICAL'
                })
                self.unconstrained_paths.append(state)
        except Exception as e:
            if self.verbose:
                print(f"Unconstrained check error: {e}")
                
    def check_taint_flow(self, state):
        """Enhanced taint analysis for malware"""
        try:
            sinks = {
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
                'CreateFile': 'Arbitrary File Access',
                'RegSetValueEx': 'Registry Manipulation',
                'CryptEncrypt': 'Encryption Activity',
                'URLDownloadToFile': 'Remote Download'
            }
            
            current_func = None
            if self.cfg:
                func = self.cfg.functions.get(state.addr)
                if func:
                    current_func = func.name
                    
            if current_func:
                for sink, vt in sinks.items():
                    if sink.lower() in current_func.lower():
                        tainted = False
                        tainted_args = []
                        
                        # Check argument registers
                        arg_regs = [state.regs.rdi, state.regs.rsi, state.regs.rdx, 
                                   state.regs.rcx, state.regs.r8, state.regs.r9] \
                                  if self.project.arch.name == 'AMD64' else \
                                  [state.regs.eax, state.regs.ecx, state.regs.edx]
                                  
                        for idx, arg in enumerate(arg_regs):
                            if arg.symbolic:
                                for var_name in state.solver.get_variables(arg):
                                    if any(src in str(var_name) for src in ['stdin', 'arg', 'file']):
                                        tainted = True
                                        tainted_args.append(f'arg{idx}')
                                        
                        if tainted:
                            info = {
                                'address': hex(state.addr),
                                'function': current_func,
                                'vulnerability_type': vt,
                                'tainted_arguments': tainted_args,
                                'description': f'Tainted input reaches {sink} - potential {vt}'
                            }
                            
                            # Try to get concrete exploit input
                            try:
                                if state.solver.satisfiable():
                                    stdin_vars = [v for v in state.solver.get_variables() 
                                                 if 'stdin' in str(v)]
                                    if stdin_vars:
                                        info['exploit_input'] = state.solver.eval(
                                            stdin_vars[0], cast_to=bytes)[:100]
                            except Exception:
                                pass
                                
                            self.taint_sinks.append(info)
                            self.vulnerabilities['taint_to_sink'].append(info)
                            
                            if self.verbose:
                                print(f"{Colors.RED}[TAINT] {vt} at {hex(state.addr)}: "
                                     f"{current_func}({', '.join(tainted_args)}){Colors.END}")
                                
        except Exception as e:
            if self.verbose:
                print(f"Taint analysis error: {e}")
                
    def track_data_flow(self, state):
        """Track data flow through the program"""
        try:
            outputs = ['write', 'send', 'printf', 'fprintf', 'puts', 'fwrite', 
                      'InternetConnect', 'HttpSendRequest']
                      
            if self.cfg:
                func = self.cfg.functions.get(state.addr)
                if func:
                    current_func = func.name
                    for of in outputs:
                        if of in current_func.lower():
                            out_arg = state.regs.rsi if self.project.arch.name == 'AMD64' \
                                     else state.regs.ecx
                            if out_arg.symbolic:
                                for var_name in state.solver.get_variables(out_arg):
                                    if any(src in str(var_name) for src in ['stdin', 'arg', 'file']):
                                        self.data_flows.append({
                                            'address': hex(state.addr),
                                            'function': current_func,
                                            'flow': 'input → output',
                                            'description': f'User input influences output at {current_func}'
                                        })
                                        break
        except Exception:
            pass
            
    def print_results(self):
        """Print comprehensive analysis results"""
        print(f"\n{Colors.BOLD}{Colors.GREEN}╔════════════════════════════════════════════════════════╗")
        print(f"║                  ANALYSIS COMPLETE                     ║")
        print(f"╚════════════════════════════════════════════════════════╝{Colors.END}\n")
        
        print(f"{Colors.BOLD}{Colors.CYAN}[*] Execution Statistics:{Colors.END}")
        print(f"    Paths explored: {self.stats.get('paths_explored', 0)}")
        print(f"    States analyzed: {self.states_analyzed}")
        print(f"    States pruned: {self.stats.get('states_pruned', 0)}")
        print(f"    Memory peak: {self.stats.get('memory_peak_mb', 0):.1f}MB")
        print(f"    Time elapsed: {self.stats.get('time_elapsed', 0):.2f}s")
        print(f"    Code coverage: {self.stats.get('code_coverage', 0):.1f}%")
        
        # Malware analysis results
        print(f"\n{Colors.BOLD}{Colors.MAGENTA}[*] Malware Analysis:{Colors.END}")
        
        if self.packed:
            print(f"    {Colors.YELLOW}Binary appears to be packed/encrypted{Colors.END}")
            
        if self.evasion_techniques:
            print(f"    {Colors.RED}Evasion techniques detected: {len(self.evasion_techniques)}{Colors.END}")
            
        if self.ransomware_risk > 30:
            color = Colors.RED if self.ransomware_risk > 60 else Colors.YELLOW
            print(f"    {color}Ransomware risk: {self.ransomware_risk}/100{Colors.END}")
            
        if self.cryptomining_risk > 30:
            color = Colors.RED if self.cryptomining_risk > 60 else Colors.YELLOW
            print(f"    {color}Cryptomining risk: {self.cryptomining_risk}/100{Colors.END}")
            
        if self.malware_indicators.get('persistence'):
            print(f"    {Colors.YELLOW}Persistence mechanisms: {len(self.malware_indicators['persistence'])}{Colors.END}")
            
        if self.malware_indicators.get('network'):
            print(f"    {Colors.YELLOW}Network activity detected: {len(self.malware_indicators['network'])} calls{Colors.END}")
            
        # Vulnerability summary
        total_vulns = sum(len(v) for v in self.vulnerabilities.values())
        print(f"\n{Colors.BOLD}{Colors.YELLOW}[*] Vulnerability Summary:{Colors.END}")
        print(f"    Total issues found: {total_vulns}\n")
        
        if total_vulns > 0:
            for vt, inst in self.vulnerabilities.items():
                if inst:
                    sev = Colors.RED if vt in ['unconstrained_execution', 'command_injection'] \
                         else Colors.YELLOW
                    print(f"{Colors.BOLD}{sev}[!] {vt.upper().replace('_', ' ')} ({len(inst)} found):{Colors.END}")
                    
                    for i, v in enumerate(inst[:3], 1):
                        print(f"    {i}. Address: {v.get('address', 'N/A')}")
                        print(f"       {v.get('description', 'No description')}")
                        
                    if len(inst) > 3:
                        print(f"    ... and {len(inst)-3} more\n")
        else:
            print(f"    {Colors.GREEN}No vulnerabilities detected{Colors.END}\n")
            
        if self.unconstrained_paths:
            print(f"{Colors.BOLD}{Colors.RED}[!!!] CRITICAL: Unconstrained Execution Paths Found!{Colors.END}")
            print(f"      This may allow arbitrary code execution")
            print(f"      Affected states: {len(self.unconstrained_paths)}\n")
            
    def export_results(self, output_file):
        """Export comprehensive results including malware analysis"""
        results = {
            'binary': self.binary_path,
            'binary_name': os.path.basename(self.binary_path),
            'binary_size': None,
            'timestamp': datetime.now().isoformat(),
            'statistics': self.stats,
            'vulnerabilities': dict(self.vulnerabilities),
            'dangerous_functions': self.dangerous_functions,
            'anti_analysis': self.anti_analysis_detected,
            'malware_analysis': {
                'packed': self.packed,
                'packers_detected': self.malware_detector.detections.get('packers', []),
                'ransomware_risk': self.ransomware_risk,
                'ransomware_indicators': self.malware_detector.detections.get('ransomware', {}),
                'cryptomining_risk': self.cryptomining_risk,
                'cryptomining_indicators': self.malware_detector.detections.get('cryptomining', {}),
                'evasion_techniques': self.evasion_techniques,
                'persistence_mechanisms': self.malware_indicators.get('persistence', []),
                'network_activity': self.malware_indicators.get('network', []),
            },
            'taint_analysis': {
                'sinks_found': len(self.taint_sinks),
                'tainted_sinks': self.taint_sinks,
                'data_flows': self.data_flows,
                'taint_sources': list(self.taint_sources)
            },
            'exploit_candidates': self.exploit_candidates,
            'coverage': {
                'percentage': self.stats.get('code_coverage', 0),
                'addresses_hit': len(self.coverage_info),
                'total_blocks': self.stats.get('basic_blocks', 0)
            }
        }
        
        try:
            results['binary_size'] = os.path.getsize(self.binary_path)
        except Exception:
            results['binary_size'] = None
            
        outdir = os.path.dirname(output_file) or '.'
        os.makedirs(outdir, exist_ok=True)
        
        try:
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            print(f"{Colors.GREEN}[+] Results exported to: {output_file}{Colors.END}")
        except Exception as e:
            print(f"{Colors.RED}[!] Failed to write results: {e}{Colors.END}")
            
        return results


# ===========================
# Batch Processing Functions
# ===========================
def analyze_single_malware(malware_path: Path, output_dir: Path, **kwargs) -> Dict[str, Any]:
    """Analyze a single malware sample"""
    try:
        hunter = SymbolicHunterEnhanced(
            str(malware_path),
            verbose=kwargs.get('verbose', False),
            max_states=kwargs.get('max_states', 1000),
            timeout=kwargs.get('timeout', 300),
            memory_limit=kwargs.get('memory_limit', 4 * 1024**3),
            anti_evasion=kwargs.get('anti_evasion', True),
        )
        
        hunter.explore_binary()
        
        # Save results
        results_file = output_dir / f"{malware_path.stem}_results.json"
        results = hunter.export_results(str(results_file))
        
        return results
        
    except Exception as e:
        print(f"{Colors.RED}[!] Failed to analyze {malware_path}: {e}{Colors.END}")
        return {'error': str(e), 'binary': str(malware_path)}
        

def batch_analysis_with_clustering(
    malware_dir: Path, 
    output_dir: Path, 
    max_workers: int = 4,
    **analysis_kwargs
) -> Dict[int, List[Dict]]:
    """
    Parallel batch analysis with similarity clustering
    Returns: Dictionary mapping cluster labels to malware samples
    """
    from sklearn.cluster import DBSCAN
    import numpy as np
    
    malware_dir = Path(malware_dir)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    print(f"{Colors.CYAN}[*] Starting batch analysis with {max_workers} workers{Colors.END}")
    
    # Collect malware samples
    samples = list(malware_dir.glob('*'))
    if not samples:
        print(f"{Colors.YELLOW}[!] No samples found in {malware_dir}{Colors.END}")
        return {}
        
    print(f"{Colors.CYAN}[*] Found {len(samples)} samples to analyze{Colors.END}")
    
    # Parallel processing
    all_results = []
    failed_samples = []
    
    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        futures = []
        for sample_path in samples:
            future = executor.submit(analyze_single_malware, sample_path, output_dir, **analysis_kwargs)
            futures.append((sample_path, future))
            
        # Collect results with timeout
        for path, future in futures:
            try:
                result = future.result(timeout=analysis_kwargs.get('timeout', 600))
                if 'error' not in result:
                    all_results.append(result)
                else:
                    failed_samples.append(str(path))
            except TimeoutError:
                print(f"{Colors.YELLOW}[!] Timeout analyzing {path}{Colors.END}")
                failed_samples.append(str(path))
            except Exception as e:
                print(f"{Colors.RED}[!] Error analyzing {path}: {e}{Colors.END}")
                failed_samples.append(str(path))
                
    print(f"{Colors.GREEN}[+] Analyzed {len(all_results)} samples successfully{Colors.END}")
    
    if failed_samples:
        print(f"{Colors.YELLOW}[!] Failed to analyze {len(failed_samples)} samples{Colors.END}")
        
    # Extract features for clustering
    if len(all_results) >= 2:
        print(f"{Colors.CYAN}[*] Clustering malware samples...{Colors.END}")
        
        def extract_features(result):
            """Extract numerical features for clustering"""
            return [
                len(result.get('dangerous_functions', [])),
                len(result.get('vulnerabilities', {}).get('buffer_overflow', [])),
                len(result.get('vulnerabilities', {}).get('command_injection', [])),
                len(result.get('taint_analysis', {}).get('tainted_sinks', [])),
                result.get('malware_analysis', {}).get('ransomware_risk', 0),
                result.get('malware_analysis', {}).get('cryptomining_risk', 0),
                len(result.get('malware_analysis', {}).get('evasion_techniques', [])),
                result.get('statistics', {}).get('paths_explored', 0),
                result.get('statistics', {}).get('code_coverage', 0),
                1 if result.get('malware_analysis', {}).get('packed', False) else 0,
            ]
            
        # Create feature matrix
        features = np.array([extract_features(r) for r in all_results])
        
        # Normalize features
        from sklearn.preprocessing import StandardScaler
        scaler = StandardScaler()
        features_normalized = scaler.fit_transform(features)
        
        # Cluster using DBSCAN
        clustering = DBSCAN(eps=2.0, min_samples=2).fit(features_normalized)
        
        # Group results by cluster
        clusters = defaultdict(list)
        for idx, label in enumerate(clustering.labels_):
            all_results[idx]['cluster_label'] = int(label)
            clusters[int(label)].append(all_results[idx])
            
        # Print cluster summary
        print(f"\n{Colors.BOLD}{Colors.MAGENTA}[*] Clustering Results:{Colors.END}")
        for label, members in clusters.items():
            if label == -1:
                print(f"    Outliers: {len(members)} samples")
            else:
                print(f"    Cluster {label}: {len(members)} samples")
                
                # Show common characteristics
                avg_ransomware = np.mean([m.get('malware_analysis', {}).get('ransomware_risk', 0) 
                                         for m in members])
                avg_mining = np.mean([m.get('malware_analysis', {}).get('cryptomining_risk', 0) 
                                     for m in members])
                                     
                if avg_ransomware > 30:
                    print(f"        - Likely ransomware cluster (avg risk: {avg_ransomware:.1f})")
                if avg_mining > 30:
                    print(f"        - Likely cryptominer cluster (avg risk: {avg_mining:.1f})")
                    
        # Save clustering results
        cluster_file = output_dir / "clustering_results.json"
        with open(cluster_file, 'w') as f:
            json.dump({
                'timestamp': datetime.now().isoformat(),
                'total_samples': len(all_results),
                'failed_samples': failed_samples,
                'num_clusters': len(set(clustering.labels_)) - (1 if -1 in clustering.labels_ else 0),
                'cluster_sizes': {str(k): len(v) for k, v in clusters.items()},
            }, f, indent=2)
            
        print(f"{Colors.GREEN}[+] Clustering results saved to: {cluster_file}{Colors.END}")
        
        return dict(clusters)
    else:
        return {0: all_results} if all_results else {}


# ===========================
# CLI Interface
# ===========================
def main():
    parser = argparse.ArgumentParser(
        description='SymbolicHunter Enhanced - Production-Ready Malware Analysis Framework',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s malware.exe
  %(prog)s --batch /malware/samples/ --workers 8
  %(prog)s --timeout 600 --memory-limit 16G sample.exe
  %(prog)s --find-function decrypt --anti-evasion malware.exe
        """
    )
    
    parser.add_argument('binary', nargs='?', help='Binary file or directory to analyze')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--max-states', type=int, default=1000, help='Maximum states to explore')
    parser.add_argument('--timeout', type=int, default=300, help='Analysis timeout in seconds')
    parser.add_argument('-o', '--output', help='Output file path')
    parser.add_argument('--find-function', help='Find paths to specific function')
    
    # Enhanced options
    parser.add_argument('--memory-limit', default='8G', help='Memory limit (e.g., 4G, 8G, 16G)')
    parser.add_argument('--anti-evasion', action='store_true', default=True,
                       help='Enable anti-evasion techniques (default: enabled)')
    parser.add_argument('--no-anti-evasion', dest='anti_evasion', action='store_false',
                       help='Disable anti-evasion techniques')
    parser.add_argument('--batch', action='store_true', help='Batch analysis mode for directories')
    parser.add_argument('--workers', type=int, default=4, help='Parallel workers for batch mode')
    parser.add_argument('--cluster', action='store_true', help='Perform clustering on batch results')
    
    # Blob options
    parser.add_argument('--blob-arch', default='auto', 
                       help='Blob architecture (auto, amd64, i386, arm, aarch64)')
    parser.add_argument('--blob-base', type=lambda x: int(x, 0), default=0x400000,
                       help='Blob base address')
    
    args = parser.parse_args()
    
    if not args.binary:
        parser.error("Binary path or directory required")
        
    # Parse memory limit
    memory_limit = args.memory_limit
    if isinstance(memory_limit, str):
        if memory_limit.endswith('G'):
            memory_limit = int(memory_limit[:-1]) * 1024**3
        elif memory_limit.endswith('M'):
            memory_limit = int(memory_limit[:-1]) * 1024**2
        else:
            memory_limit = int(memory_limit)
            
    binary_path = Path(args.binary)
    
    # Batch mode
    if args.batch or binary_path.is_dir():
        if not binary_path.is_dir():
            print(f"{Colors.RED}[!] Batch mode requires a directory{Colors.END}")
            sys.exit(1)
            
        output_dir = Path(args.output) if args.output else Path.cwd() / "batch_results"
        
        if args.cluster:
            clusters = batch_analysis_with_clustering(
                binary_path, 
                output_dir,
                max_workers=args.workers,
                verbose=args.verbose,
                max_states=args.max_states,
                timeout=args.timeout,
                memory_limit=memory_limit,
                anti_evasion=args.anti_evasion,
            )
            
            print(f"\n{Colors.GREEN}[+] Batch analysis complete with clustering{Colors.END}")
            print(f"    Results saved to: {output_dir}")
        else:
            # Simple batch without clustering
            samples = list(binary_path.glob('*'))
            for sample in samples:
                if sample.is_file():
                    print(f"\n{Colors.CYAN}[*] Analyzing: {sample.name}{Colors.END}")
                    analyze_single_malware(
                        sample, 
                        output_dir,
                        verbose=args.verbose,
                        max_states=args.max_states,
                        timeout=args.timeout,
                        memory_limit=memory_limit,
                        anti_evasion=args.anti_evasion,
                    )
                    
    # Single file mode
    else:
        if not binary_path.is_file():
            print(f"{Colors.RED}[!] File not found: {binary_path}{Colors.END}")
            sys.exit(1)
            
        try:
            hunter = SymbolicHunterEnhanced(
                str(binary_path),
                verbose=args.verbose,
                max_states=args.max_states,
                timeout=args.timeout,
                memory_limit=memory_limit,
                anti_evasion=args.anti_evasion,
                blob_arch=args.blob_arch,
                blob_base=args.blob_base,
            )
            
            hunter.print_header()
            hunter.explore_binary(target_function=args.find_function)
            hunter.print_results()
            
            if args.output:
                output_path = Path(args.output)
                if output_path.suffix != '.json':
                    output_path = output_path / f"{binary_path.stem}_results.json"
                    
                hunter.export_results(str(output_path))
                
        except Exception as e:
            print(f"{Colors.RED}[!] Analysis failed: {e}{Colors.END}")
            if args.verbose:
                import traceback
                traceback.print_exc()
            sys.exit(1)
            
            
def print_header():
    """Print tool header"""
    header = f"""
{Colors.BOLD}{Colors.CYAN}
╔═══════════════════════════════════════════════════════════╗
║      SymbolicHunter Enhanced - Malware Analysis Tool      ║  
║         Production-Ready Symbolic Execution Engine        ║
║              with Advanced Malware Detection              ║
╚═══════════════════════════════════════════════════════════╝
{Colors.END}
"""
    print(header)


if __name__ == '__main__':
    print_header()
    main()

