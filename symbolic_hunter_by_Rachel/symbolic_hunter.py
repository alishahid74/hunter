#!/usr/bin/env python3
"""
SymbolicHunter - Comprehensive Symbolic Execution Analysis Tool
Automatically detects vulnerabilities and analyzes binaries using angr

Enhancements:
- Directory input support (file or folder) with smarter candidate detection
- Skip obvious text/source/script files unless --all is used
- Blob backend fallback for unrecognized binaries (configurable)
- Quiet claripy warnings by default (toggle with --no-quiet-claripy)
- JSON + HTML report generation (if modules/reporting.py is present)
- NEW: Signature bundle output (YARA, Suricata/Snort rules, Sigma YAML, IOC text)
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
from typing import Optional, List, Dict, Any
from archinfo import arch_from_id
import hashlib
import uuid
import re

# =========================
# Colors for pretty prints
# =========================
class Colors:
    RED = '\033[91m'; GREEN = '\033[92m'; YELLOW = '\033[93m'; BLUE = '\033[94m'
    MAGENTA = '\033[95m'; CYAN = '\033[96m'; WHITE = '\033[97m'; BOLD = '\033[1m'; END = '\033[0m'

# =====================================
# Helpers: detection & directory walks
# =====================================
BINARY_MAGIC: Dict[bytes, str] = {
    b'MZ': 'PE',                    # Windows PE
    b'\x7fELF': 'ELF',              # ELF
    b'\xfe\xed\xfa\xce': 'MACHO',   # Mach-O 32-bit BE
    b'\xce\xfa\xed\xfe': 'MACHO',   # Mach-O 32-bit LE
    b'\xfe\xed\xfa\xcf': 'MACHO',   # Mach-O 64-bit BE
    b'\xcf\xfa\xed\xfe': 'MACHO',   # Mach-O 64-bit LE
    b'\xca\xfe\xba\xbe': 'FAT_MACHO' # Mach-O fat/universal
}
TEXT_SAMPLE_BYTES = 2048
TEXTY_EXTS = {".c", ".cc", ".cpp", ".h", ".hpp", ".py", ".sh", ".js", ".ts", ".rs", ".go", ".java", ".txt", ".md"}

def _head(path: Path, size: int = TEXT_SAMPLE_BYTES) -> bytes:
    try:
        with open(path, "rb") as f:
            return f.read(size)
    except Exception:
        return b""

def guess_file_kind(path: Path) -> str:
    """
    Heuristics to decide if a file looks like a native binary we should try.
    Returns: 'PE','ELF','MACHO','FAT_MACHO','EXECUTABLE','BINARY','SCRIPT','TEXT','UNKNOWN'
    """
    data = _head(path)
    for magic, name in BINARY_MAGIC.items():
        if data.startswith(magic):
            return name
    if data.startswith(b"#!"):
        return "SCRIPT"
    if path.suffix.lower() in TEXTY_EXTS:
        return "TEXT"
    if data:
        if b"\x00" in data:
            return "BINARY"
        try:
            sample = data.decode("utf-8", errors="ignore")
            nonprint = sum(1 for ch in sample if ord(ch) < 9 or (13 < ord(ch) < 32))
            if nonprint < max(5, len(sample) // 50):
                return "TEXT"
        except Exception:
            pass
    try:
        if (path.stat().st_mode & 0o111):
            return "EXECUTABLE"
    except Exception:
        pass
    return "UNKNOWN"

def collect_candidate_files(root: Path, recursive: bool = True, include_all: bool = False) -> List[Path]:
    """
    Walk `root` (file or dir) and return paths to analyze.
    - include_all=True: include everything except obvious TEXT/SCRIPT
    - include_all=False: include only files that look like native binaries
    """
    def _include(p: Path) -> bool:
        kind = guess_file_kind(p)
        if include_all:
            return kind not in {"TEXT", "SCRIPT"}
        return kind in {"PE", "ELF", "MACHO", "FAT_MACHO", "EXECUTABLE", "BINARY"}

    if root.is_file():
        return [root] if _include(root) else []

    it = root.rglob("*") if recursive else root.iterdir()
    out: List[Path] = []
    for p in it:
        if p.is_file() and _include(p):
            out.append(p)
    return sorted(out)

# =========================
# Signature bundle helpers
# =========================
def _file_hashes(p: Path) -> Dict[str, str]:
    h_md5 = hashlib.md5()
    h_sha1 = hashlib.sha1()
    h_sha256 = hashlib.sha256()
    try:
        with open(p, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h_md5.update(chunk); h_sha1.update(chunk); h_sha256.update(chunk)
        return {"md5": h_md5.hexdigest(), "sha1": h_sha1.hexdigest(), "sha256": h_sha256.hexdigest()}
    except Exception:
        return {"md5": "", "sha1": "", "sha256": ""}

def _sanitize_name_for_rule(name: str) -> str:
    name = re.sub(r"[^A-Za-z0-9_]", "_", name)
    if not name or not name[0].isalpha():
        name = "SH_" + name
    return name[:64]  # keep it readable

def _yara_rule_text(bin_name: str, kind: str, hashes: Dict[str, str], suspicious_strings: List[str]) -> str:
    rule_name = _sanitize_name_for_rule(f"SH_{bin_name}_{hashes['sha256'][:8]}")
    # limit strings to keep rule sane
    uniq = []
    for s in suspicious_strings:
        s = s.strip()
        if s and s not in uniq:
            uniq.append(s)
    uniq = uniq[:12]

    magic_cond = []
    # PE: MZ (0x5A4D)
    magic_cond.append("uint16(0) == 0x5A4D")  # PE
    magic_cond.append("uint32(0) == 0x464C457F")  # ELF (\x7FELF)
    # Mach-O common magics (multiple endianness/32/64)
    magic_cond.extend([
        "uint32(0) == 0xFEEDFACE", "uint32(0) == 0xCEFAEDFE",
        "uint32(0) == 0xFEEDFACF", "uint32(0) == 0xCFFAEDFE",
        "uint32(0) == 0xCAFEBABE"
    ])
    magic_clause = " or ".join(magic_cond)

    strings_block = ""
    if uniq:
        strings_block = "\n  strings:\n" + "\n".join([f'    $s{i} = "{u}" nocase ascii' for i, u in enumerate(uniq, 1)])

    return f'''import "hash"

rule {rule_name}
{{
  meta:
    author = "SymbolicHunter"
    date = "{datetime.now().date().isoformat()}"
    description = "Auto-generated from analysis of {bin_name}"
    sha256 = "{hashes['sha256']}"
    md5 = "{hashes['md5']}"
    source = "SymbolicHunter"

{strings_block if strings_block else ""}
  condition:
    (hash.sha256(0, filesize) == "{hashes['sha256']}") or
    ({magic_clause} and any of ($s*))
}}
'''.rstrip() + "\n"

def _suricata_rules_text(bin_name: str, hashes: Dict[str, str]) -> str:
    # Create stable SIDs derived from SHA1 (stay under Snort's typical limits)
    base = int(hashes['sha1'][:7], 16) if hashes['sha1'] else 1000000
    sid1 = 2000000 + (base % 500000)
    sid2 = sid1 + 1
    # Suricata supports filesha256 and filemd5 in file inspection contexts (HTTP/SMTP/FTP/etc.)
    return f'''# Auto-generated by SymbolicHunter for {bin_name}

alert http any any -> any any (msg:"SymbolicHunter: Known file by SHA256 {bin_name}"; filesha256:"{hashes['sha256']}"; sid:{sid1}; rev:1;)
alert http any any -> any any (msg:"SymbolicHunter: Known file by MD5 {bin_name}"; filemd5:"{hashes['md5']}"; sid:{sid2}; rev:1;)
'''.rstrip() + "\n"

def _sigma_yaml_text(bin_name: str, kind: str, hashes: Dict[str, str]) -> str:
    prod = "windows" if kind == "PE" else ("macos" if "MACHO" in kind else "linux")
    # Image suffix depending OS
    if prod == "windows":
        suffix = "\\" + bin_name
    else:
        suffix = "/" + bin_name
    return f'''title: SymbolicHunter - Execution of {bin_name}
id: {str(uuid.uuid4())}
status: experimental
description: Detects execution of a known suspicious binary identified by SymbolicHunter analysis
author: SymbolicHunter
date: {datetime.now().date().isoformat()}
references: []
logsource:
  category: process_creation
  product: {prod}
detection:
  selection_hash1:
    Hashes|contains: "{hashes['sha256']}"
  selection_hash2:
    sha256: "{hashes['sha256']}"
  selection_name:
    Image|endswith: "{suffix}"
  condition: 1 of selection_*
falsepositives:
  - Unlikely
level: high
'''.rstrip() + "\n"

def _ioc_text(bin_path: Path, kind: str, hashes: Dict[str, str], results: Dict[str, Any]) -> str:
    apis = sorted(set([d.get("name", "") for d in results.get("dangerous_functions", []) if d.get("name")]))
    sinks = results.get("taint_analysis", {}).get("tainted_sinks", [])
    lines = [
        f"file_path: {str(bin_path)}",
        f"file_name: {bin_path.name}",
        f"file_size: {os.path.getsize(bin_path) if bin_path.exists() else 'unknown'}",
        f"file_type: {kind}",
        f"md5: {hashes['md5']}",
        f"sha1: {hashes['sha1']}",
        f"sha256: {hashes['sha256']}",
        f"dang_api_count: {len(apis)}",
    ]
    if apis:
        lines.append("dangerous_apis: " + ", ".join(apis[:20]) + ("" if len(apis) <= 20 else ", ..."))
    if sinks:
        lines.append(f"taint_sinks_count: {len(sinks)}")
        # include a couple examples
        for s in sinks[:3]:
            lines.append(f"taint_sink: {s.get('function','?')} @ {s.get('address','?')} -> {s.get('vulnerability_type','?')}")
    return "\n".join(lines) + "\n"

def generate_signature_bundle(bin_path: Path, results: Dict[str, Any], outdir: Path) -> Dict[str, str]:
    """
    Create signatures/IOCs for this binary next to the JSON results.
    Returns a dict of created file paths.
    """
    outdir.mkdir(parents=True, exist_ok=True)
    bin_name = bin_path.name
    kind = guess_file_kind(bin_path)
    hashes = _file_hashes(bin_path)

    # choose some strings for YARA from dangerous functions
    suspicious_strings = [d.get("name","") for d in results.get("dangerous_functions", []) if d.get("name")]
    # Ensure uniqueness and keep short
    suspicious_strings = list(dict.fromkeys(suspicious_strings))[:12]

    yara_text = _yara_rule_text(bin_name, kind, hashes, suspicious_strings)
    suri_text = _suricata_rules_text(bin_name, hashes)
    sigma_text = _sigma_yaml_text(bin_name, kind, hashes)
    ioc_text = _ioc_text(bin_path, kind, hashes, results)

    created = {}
    try:
        yar_path = outdir / f"{bin_name}.yar"
        with open(yar_path, "w") as f: f.write(yara_text)
        created["yar"] = str(yar_path)
    except Exception as e:
        print(f"{Colors.YELLOW}[!] Failed to write YARA: {e}{Colors.END}")

    try:
        rules_path = outdir / f"{bin_name}.rules"
        with open(rules_path, "w") as f: f.write(suri_text)
        created["rules"] = str(rules_path)
    except Exception as e:
        print(f"{Colors.YELLOW}[!] Failed to write Suricata rules: {e}{Colors.END}")

    try:
        yml_path = outdir / f"{bin_name}.yml"
        with open(yml_path, "w") as f: f.write(sigma_text)
        created["yml"] = str(yml_path)
    except Exception as e:
        print(f"{Colors.YELLOW}[!] Failed to write Sigma YAML: {e}{Colors.END}")

    try:
        ioc_path = outdir / f"{bin_name}_iocs.txt"
        with open(ioc_path, "w") as f: f.write(ioc_text)
        created["iocs"] = str(ioc_path)
    except Exception as e:
        print(f"{Colors.YELLOW}[!] Failed to write IOC text: {e}{Colors.END}")

    if created:
        print(f"{Colors.GREEN}[+] Signature bundle written to: {outdir}{Colors.END}")
        for k, v in created.items():
            print(f"    - {k}: {v}")
    return created

# ======================
# Core Analyzer Class
# ======================
class SymbolicHunter:
    def __init__(
        self,
        binary_path: str,
        verbose: bool = False,
        max_states: int = 1000,
        timeout: int = 300,
        *,
        blob_fallback: bool = True,
        blob_arch: str = "amd64",
        blob_base: int = 0x400000,
        blob_entry: Optional[int] = None,
        quiet_claripy: bool = True,
    ):
        self.binary_path = binary_path
        self.verbose = verbose
        self.max_states = max_states
        self.timeout = timeout

        # blob options
        self.blob_fallback = blob_fallback
        self.blob_arch = blob_arch
        self.blob_base = blob_base
        self.blob_entry = blob_entry

        # quiet claripy spam unless verbose or user disables
        if quiet_claripy and not verbose:
            logging.getLogger("claripy").setLevel(logging.ERROR)
            logging.getLogger("claripy.ast").setLevel(logging.ERROR)
            logging.getLogger("claripy.ast.bv").setLevel(logging.ERROR)

        # Results
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

        self.stats = {
            'paths_explored': 0, 'states_analyzed': 0, 'constraints_solved': 0,
            'time_elapsed': 0, 'functions_discovered': 0, 'basic_blocks': 0, 'code_coverage': 0
        }

        # logging
        logging.getLogger('angr').setLevel(logging.INFO if verbose else logging.WARNING)

        print(f"{Colors.BOLD}{Colors.CYAN}[*] Loading binary: {binary_path}{Colors.END}")
        self._load_project()

    # ------------ project loading (with Blob fallback) ------------
    def _load_project(self):
        try:
            self.project = angr.Project(self.binary_path, auto_load_libs=False)
            print(f"{Colors.GREEN}[+] Binary loaded successfully{Colors.END}")
        except Exception as e:
            print(f"{Colors.YELLOW}[!] Failed to load normally: {e}{Colors.END}")
            if not self.blob_fallback:
                raise
            print(f"{Colors.CYAN}[*] Trying Blob backend fallback (arch={self.blob_arch}, base=0x{self.blob_base:x}){Colors.END}")
            try:
                arch = arch_from_id(self.blob_arch)
                main_opts = {'backend': 'blob', 'arch': arch, 'base_addr': self.blob_base}
                if self.blob_entry is not None:
                    main_opts['entry_point'] = self.blob_entry
                self.project = angr.Project(self.binary_path, main_opts=main_opts, auto_load_libs=False)
                print(f"{Colors.GREEN}[+] Loaded with Blob backend{Colors.END}")
            except Exception as e2:
                print(f"{Colors.RED}[!] Blob fallback failed: {e2}{Colors.END}")
                raise

        try:
            print(f"    Architecture: {self.project.arch.name}")
            print(f"    Entry point: {hex(self.project.entry)}")
            print(f"    Base address: {hex(self.project.loader.main_object.min_addr)}")
        except Exception:
            pass

        print(f"\n{Colors.CYAN}[*] Performing CFG analysis...{Colors.END}")
        try:
            self.cfg = self.project.analyses.CFGFast()
            self.stats['functions_discovered'] = len(self.cfg.functions)
            try:
                self.stats['basic_blocks'] = len(list(self.cfg.graph.nodes()))
            except Exception:
                self.stats['basic_blocks'] = 0
            print(f"{Colors.GREEN}[+] CFG analysis complete{Colors.END}")
            print(f"    Functions discovered: {self.stats['functions_discovered']}")
            print(f"    Basic blocks: {self.stats['basic_blocks']}")
            self.identify_dangerous_functions()
        except Exception as e:
            print(f"{Colors.YELLOW}[!] CFG analysis failed: {e}{Colors.END}")
            if self.verbose:
                import traceback; traceback.print_exc()

    def print_header(self):
        header = f"""
{Colors.BOLD}{Colors.CYAN}
╔═══════════════════════════════════════════════════════════╗
║           SymbolicHunter - angr Analysis Tool             ║
║     Comprehensive Symbolic Execution Vulnerability        ║
║              Detection and Path Analysis                  ║
╚═══════════════════════════════════════════════════════════╝
{Colors.END}
"""
        print(header)

    def identify_dangerous_functions(self):
        if not self.cfg:
            return
        dangerous_apis = {
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
        print(f"\n{Colors.CYAN}[*] Scanning for dangerous API calls...{Colors.END}")
        api_categories = defaultdict(list)
        for func_addr, func in self.cfg.functions.items():
            func_name = func.name
            for category, apis in dangerous_apis.items():
                for dangerous in apis:
                    if dangerous.lower() in func_name.lower():
                        self.dangerous_functions.append({
                            'name': func_name,'address': hex(func_addr),'type': dangerous,'category': category
                        })
                        api_categories[category].append(func_name)
                        if category in ['anti_debug','anti_vm']:
                            self.anti_analysis_detected.append({
                                'technique': category,'function': func_name,'address': hex(func_addr)
                            })
        if self.dangerous_functions:
            print(f"{Colors.YELLOW}[!] Found {len(self.dangerous_functions)} dangerous API calls{Colors.END}")
            for category, funcs in api_categories.items():
                color = Colors.RED if category in ['process','anti_debug','anti_vm'] else Colors.YELLOW
                print(f"    {color}[{category.upper()}]{Colors.END} {len(funcs)} calls")
            if self.verbose:
                for func in self.dangerous_functions[:10]:
                    print(f"    - {func['name']} at {func['address']}")
        else:
            print(f"{Colors.GREEN}[+] No known dangerous APIs detected{Colors.END}")
        if self.anti_analysis_detected:
            print(f"\n{Colors.RED}[!!!] Anti-Analysis Techniques Detected!{Colors.END}")
            print(f"      This binary may evade debugging/analysis")
            for tech in self.anti_analysis_detected:
                print(f"      - {tech['technique']}: {tech['function']} at {tech['address']}")

    # --- vulnerability checks (condensed for brevity) ---
    def check_buffer_overflow(self, state):
        try:
            regs = [state.regs.rax, state.regs.rbx, state.regs.rcx, state.regs.rdx, state.regs.rsi, state.regs.rdi] \
                if self.project.arch.name == 'AMD64' else \
                [state.regs.eax, state.regs.ebx, state.regs.ecx, state.regs.edx, state.regs.esi, state.regs.edi]
            for reg in regs:
                if getattr(reg, "symbolic", False):
                    try:
                        if state.solver.satisfiable(extra_constraints=[reg > 0x7fff0000]):
                            self.vulnerabilities['buffer_overflow'].append({
                                'address': hex(state.addr),'register': str(reg),
                                'description': 'Symbolic pointer could overflow buffer bounds'
                            }); break
                    except Exception: pass
        except Exception as e:
            if self.verbose: print(f"    Buffer overflow check error: {e}")

    def check_integer_overflow(self, state):
        try:
            for var in state.solver.get_variables():
                if any(t in str(var) for t in ("stdin","arg","file")):
                    try:
                        if state.solver.satisfiable(extra_constraints=[var > 0x7fffffff]):
                            self.vulnerabilities['integer_overflow'].append({
                                'address': hex(state.addr),'variable': str(var),
                                'description': 'Symbolic integer can overflow'
                            })
                    except Exception: pass
        except Exception as e:
            if self.verbose: print(f"    Integer overflow check error: {e}")

    def check_format_string(self, state):
        try:
            fmt_arg = state.regs.rsi if self.project.arch.name == 'AMD64' else state.regs.esi
            if getattr(fmt_arg, "symbolic", False):
                self.vulnerabilities['format_string'].append({
                    'address': hex(state.addr),'description': 'Symbolic format string argument'
                })
        except Exception as e:
            if self.verbose: print(f"    Format string check error: {e}")

    def check_null_deref(self, state):
        try:
            regs = [state.regs.rax, state.regs.rbx, state.regs.rcx, state.regs.rdx, state.regs.rsi, state.regs.rdi] \
                if self.project.arch.name == 'AMD64' else \
                [state.regs.eax, state.regs.ebx, state.regs.ecx, state.regs.edx]
        except Exception:
            regs = []
        try:
            for reg in regs:
                if getattr(reg, "symbolic", False):
                    try:
                        if state.solver.satisfiable(extra_constraints=[reg == 0]):
                            self.vulnerabilities['null_deref'].append({
                                'address': hex(state.addr),'register': str(reg),
                                'description': 'Register can be NULL and may be dereferenced'
                            })
                    except Exception: pass
        except Exception as e:
            if self.verbose: print(f"    NULL deref check error: {e}")

    def check_division_by_zero(self, state):
        try:
            block = self.project.factory.block(state.addr)
            for insn in block.capstone.insns:
                if insn.mnemonic in ['div','idiv']:
                    divisor = state.regs.rcx if self.project.arch.name == 'AMD64' else state.regs.ecx
                    if getattr(divisor, "symbolic", False):
                        try:
                            if state.solver.satisfiable(extra_constraints=[divisor == 0]):
                                self.vulnerabilities['div_by_zero'].append({
                                    'address': hex(state.addr),'description': 'Division by zero possible'
                                })
                        except Exception: pass
        except Exception as e:
            if self.verbose: print(f"    Division by zero check error: {e}")

    def check_unconstrained(self, state):
        try:
            if getattr(state.regs, "ip", None) is not None and getattr(state.regs.ip, "symbolic", False):
                self.vulnerabilities['unconstrained_execution'].append({
                    'address': hex(state.addr), 'description': 'Instruction pointer is symbolic - possible code execution',
                    'severity': 'CRITICAL'
                }); self.unconstrained_paths.append(state)
        except Exception as e:
            if self.verbose: print(f"    Unconstrained check error: {e}")

    def check_taint_flow(self, state):
        try:
            sinks = {
                'system':'Command Injection','exec':'Command Injection','popen':'Command Injection',
                'CreateProcess':'Command Injection','WinExec':'Command Injection','ShellExecute':'Command Injection',
                'strcpy':'Buffer Overflow','strcat':'Buffer Overflow','sprintf':'Buffer Overflow','gets':'Buffer Overflow',
                'scanf':'Buffer Overflow','memcpy':'Buffer Overflow',
                'printf':'Format String','fprintf':'Format String','snprintf':'Format String',
                'LoadLibrary':'Arbitrary Library Load','dlopen':'Arbitrary Library Load',
                'fopen':'Arbitrary File Access','open':'Arbitrary File Access','CreateFile':'Arbitrary File Access'
            }
            current_func = None
            if self.cfg:
                func = self.cfg.functions.get(state.addr)
                if func: current_func = func.name
            if current_func:
                for sink, vt in sinks.items():
                    if sink.lower() in current_func.lower():
                        tainted, tainted_args = False, []
                        arg_regs = [state.regs.rdi, state.regs.rsi, state.regs.rdx, state.regs.rcx, state.regs.r8, state.regs.r9] \
                            if self.project.arch.name == 'AMD64' else [state.regs.eax, state.regs.ecx, state.regs.edx]
                        for idx, arg in enumerate(arg_regs):
                            if getattr(arg,"symbolic",False):
                                for var_name in state.solver.get_variables(arg):
                                    if any(src in str(var_name) for src in ['stdin','arg','file']):
                                        tainted = True; tainted_args.append(f'arg{idx}')
                        for idx, arg in enumerate(arg_regs[:3]):
                            try:
                                if not getattr(arg,"symbolic",False) and state.solver.is_true(arg != 0):
                                    mem_val = state.memory.load(arg, 8)
                                    if getattr(mem_val,"symbolic",False):
                                        for var_name in state.solver.get_variables(mem_val):
                                            if any(src in str(var_name) for src in ['stdin','arg','file']):
                                                tainted = True; tainted_args.append(f'*arg{idx}')
                            except Exception: pass
                        if tainted:
                            info = {'address': hex(state.addr),'function': current_func,
                                    'vulnerability_type': vt,'tainted_arguments': tainted_args,
                                    'description': f'Tainted input reaches {sink} - potential {vt}'}
                            try:
                                if state.solver.satisfiable():
                                    stdin_vars = [v for v in state.solver.get_variables() if 'stdin' in str(v)]
                                    if stdin_vars:
                                        info['exploit_input'] = state.solver.eval(stdin_vars[0], cast_to=bytes)[:100]
                            except Exception: pass
                            self.taint_sinks.append(info)
                            self.vulnerabilities['taint_to_sink'].append(info)
                            if self.verbose:
                                print(f"{Colors.RED}[TAINT] {vt} at {hex(state.addr)}: {current_func}({', '.join(tainted_args)}){Colors.END}")
        except Exception as e:
            if self.verbose: print(f"    Taint analysis error: {e}")

    def track_data_flow(self, state):
        try:
            outs = ['write','send','printf','fprintf','puts','fwrite']
            if self.cfg:
                func = self.cfg.functions.get(state.addr)
                if func:
                    current_func = func.name
                    for of in outs:
                        if of in current_func.lower():
                            out_arg = state.regs.rsi if self.project.arch.name == 'AMD64' else state.regs.ecx
                            if getattr(out_arg,"symbolic",False):
                                for var_name in state.solver.get_variables(out_arg):
                                    if any(src in str(var_name) for src in ['stdin','arg','file']):
                                        self.data_flows.append({
                                            'address': hex(state.addr),'function': current_func,'flow':'input → output',
                                            'description': f'User input directly influences output at {current_func}'
                                        }); break
        except Exception: pass

    def analyze_state(self, state):
        self.stats['states_analyzed'] += 1
        self.coverage_info.add(state.addr)
        if state.addr not in self.unique_vulns:
            self.unique_vulns[state.addr] = True
            self.check_buffer_overflow(state); self.check_integer_overflow(state)
            self.check_format_string(state); self.check_null_deref(state)
            self.check_division_by_zero(state); self.check_unconstrained(state)
        self.check_taint_flow(state); self.track_data_flow(state)
        try:
            for var in state.solver.get_variables():
                if any(src in str(var) for src in ['stdin','arg','file']):
                    self.taint_sources.add(str(var))
        except Exception: pass
        for dangerous in self.dangerous_functions:
            try:
                if state.addr == int(dangerous['address'],16) and state.solver.satisfiable():
                    stdin_vars = [v for v in state.solver.get_variables() if 'stdin' in str(v)]
                    if stdin_vars:
                        concrete = state.solver.eval(stdin_vars[0], cast_to=bytes)
                        self.exploit_candidates.append({
                            'target_function': dangerous['name'],'address': dangerous['address'],
                            'category': dangerous.get('category','unknown'),'input': concrete[:100],
                            'description': f"Input reaches {dangerous['name']} - potential exploit vector"
                        })
            except Exception: pass
        try:
            if len(state.solver.constraints) > 5 and state.solver.satisfiable():
                stdin_vars = [v for v in state.solver.get_variables() if 'stdin' in str(v)]
                if stdin_vars:
                    concrete = state.solver.eval(stdin_vars[0], cast_to=bytes)
                    self.winning_inputs.append({'address': hex(state.addr),'input': concrete[:50],
                                                'num_constraints': len(state.solver.constraints)})
        except Exception: pass
        try:
            if len(state.solver.constraints) > 0 and len(self.constraints_found) < 100:
                self.constraints_found.append({
                    'address': hex(state.addr),'num_constraints': len(state.solver.constraints),
                    'constraints': [str(c) for c in list(state.solver.constraints)[:3]]
                })
        except Exception: pass

    def explore_binary(self, target_function=None):
        print(f"\n{Colors.BOLD}{Colors.YELLOW}[*] Starting symbolic execution with angr...{Colors.END}")
        print(f"    Max states: {self.max_states}"); print(f"    Timeout: {self.timeout}s\n")
        state = self.project.factory.entry_state(add_options={angr.options.LAZY_SOLVES})
        # symbolic stdin
        stdin_size = 200; stdin_data = claripy.BVS('stdin', 8*stdin_size)
        try:
            stdin_file = self.project.loader.project.simos.SimFile('stdin', content=stdin_data, size=stdin_size)
        except Exception:
            import angr.storage as _s; stdin_file = _s.SimFile('stdin', content=stdin_data, size=stdin_size)
        try:
            state.fs.insert('stdin', stdin_file); state.posix.stdin = stdin_file
        except Exception:
            try: state.posix.stdin = stdin_file
            except Exception: pass
        # argv on non-Windows
        if self.project.loader.main_object.os != 'windows':
            arg1 = claripy.BVS('arg1', 8*100)
            try: state.posix.argv = [self.project.filename, arg1]
            except Exception:
                try: state.posix.set_argv([self.project.filename, arg1])
                except Exception: pass
        else:
            print(f"{Colors.CYAN}[*] Detected Windows PE binary{Colors.END}")
        simgr = self.project.factory.simulation_manager(state)
        find_addr = None
        if target_function:
            print(f"{Colors.CYAN}[*] Searching for function: {target_function}{Colors.END}")
            for func_addr, func in self.cfg.functions.items():
                if target_function.lower() in func.name.lower():
                    find_addr = func_addr; print(f"{Colors.GREEN}[+] Found target: {func.name} at {hex(func_addr)}{Colors.END}"); break
            if not find_addr:
                print(f"{Colors.YELLOW}[!] Function '{target_function}' not found in binary{Colors.END}")
        if self.dangerous_functions:
            try:
                from angr.exploration_techniques import DFS; simgr.use_technique(DFS())
            except Exception: pass
        print(f"{Colors.CYAN}[*] Using angr exploration strategies...{Colors.END}\n")
        start_time = datetime.now(); step_count = 0; found_target = False
        try:
            while len(simgr.active) > 0 and step_count < self.max_states:
                if find_addr and not found_target:
                    for st in list(simgr.active):
                        try:
                            if st.addr == find_addr:
                                print(f"\n{Colors.GREEN}[!!!] Reached target function at {hex(find_addr)}!{Colors.END}")
                                found_target = True
                                try:
                                    if st.solver.satisfiable():
                                        stdin_vars = [v for v in st.solver.get_variables() if 'stdin' in str(v)]
                                        if stdin_vars:
                                            win = st.solver.eval(stdin_vars[0], cast_to=bytes)
                                            print(f"{Colors.MAGENTA}[+] Input to reach target:{Colors.END}")
                                            print(f"    Hex: {win[:50].hex()}"); print(f"    ASCII: {repr(win[:50])}\n")
                                            self.exploit_candidates.append({
                                                'target_function': target_function,'address': hex(find_addr),
                                                'category':'target','input': win[:100],
                                                'description': f'Input reaches target function {target_function}'
                                            })
                                except Exception: pass
                        except Exception: continue
                simgr.step(); step_count += 1
                self.stats['paths_explored'] = len(simgr.active) + len(simgr.deadended)
                try:
                    for s in list(simgr.active): self.analyze_state(s)
                except Exception: pass
                try:
                    for s in list(simgr.deadended): self.analyze_state(s)
                except Exception: pass
                try:
                    for er in list(simgr.errored):
                        if hasattr(er,'state'):
                            self.vulnerabilities['crashed_paths'].append({
                                'address': hex(er.state.addr),'error': str(er.error)[:200],
                                'description': 'Path resulted in error - possible vulnerability'
                            })
                except Exception: pass
                if step_count % 50 == 0:
                    elapsed = (datetime.now() - start_time).total_seconds()
                    print(f"{Colors.CYAN}[*] Step {step_count}: Active={len(simgr.active)}, Dead={len(simgr.deadended)}, "
                          f"Error={len(simgr.errored)}, Uncon={len(simgr.unconstrained)}, "
                          f"Exploits={len(self.exploit_candidates)}, Time={elapsed:.1f}s{Colors.END}")
                if (datetime.now() - start_time).total_seconds() > self.timeout:
                    print(f"\n{Colors.YELLOW}[!] Timeout reached{Colors.END}"); break
                if len(simgr.active) > 100:
                    print(f"{Colors.YELLOW}[!] Pruning states (too many active paths){Colors.END}")
                    simgr.active = simgr.active[:50]
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[!] Analysis interrupted by user{Colors.END}")
        except Exception as e:
            print(f"\n{Colors.RED}[!] Analysis error: {e}{Colors.END}")
            if self.verbose: import traceback; traceback.print_exc()
        self.stats['time_elapsed'] = (datetime.now() - start_time).total_seconds()
        try:
            if self.stats['basic_blocks'] > 0:
                self.stats['code_coverage'] = (len(self.coverage_info) / self.stats['basic_blocks']) * 100
        except Exception: self.stats['code_coverage'] = 0
        print(f"\n{Colors.CYAN}[*] Performing final analysis of all paths...{Colors.END}")
        for stash_name in ['active','deadended','errored','unconstrained']:
            stash = getattr(simgr, stash_name, [])
            for item in stash:
                if stash_name == 'errored' and hasattr(item,'state'):
                    self.analyze_state(item.state)
                else:
                    self.analyze_state(item)
        try:
            self.stats['states_analyzed'] = len(simgr.deadended) + len(simgr.active)
        except Exception: pass
        if target_function:
            if found_target: print(f"{Colors.GREEN}[+] Successfully found path to '{target_function}'!{Colors.END}")
            else: print(f"{Colors.YELLOW}[!] Could not find path to '{target_function}' within constraints{Colors.END}")

    def print_results(self):
        print(f"\n{Colors.BOLD}{Colors.GREEN}╔════════════════════════════════════════════════════════╗")
        print(f"║                  ANALYSIS COMPLETE                     ║")
        print(f"╚════════════════════════════════════════════════════════╝{Colors.END}\n")
        print(f"{Colors.BOLD}{Colors.CYAN}[*] Execution Statistics:{Colors.END}")
        print(f"    Paths explored: {self.stats.get('paths_explored',0)}")
        print(f"    States analyzed: {self.stats.get('states_analyzed',0)}")
        print(f"    Time elapsed: {self.stats.get('time_elapsed',0):.2f}s")
        print(f"    Constraints found: {len(self.constraints_found)}")
        total_vulns = sum(len(v) for v in self.vulnerabilities.values())
        print(f"\n{Colors.BOLD}{Colors.YELLOW}[*] Vulnerability Summary:{Colors.END}")
        print(f"    Total issues found: {total_vulns}\n")
        if total_vulns > 0:
            for vt, inst in self.vulnerabilities.items():
                if inst:
                    sev = Colors.RED if vt == 'unconstrained_execution' else Colors.YELLOW
                    print(f"{Colors.BOLD}{sev}[!] {vt.upper().replace('_',' ')} ({len(inst)} found):{Colors.END}")
                    for i, v in enumerate(inst[:5],1):
                        print(f"    {i}. Address: {v.get('address','N/A')}")
                        print(f"       {v.get('description','No description')}")
                        if 'severity' in v:
                            print(f"       Severity: {Colors.RED}{v['severity']}{Colors.END}")
                    if len(inst) > 5:
                        print(f"    ... and {len(inst)-5} more\n")
        else:
            print(f"    {Colors.GREEN}No vulnerabilities detected{Colors.END}\n")
        if self.constraints_found and self.verbose:
            print(f"{Colors.BOLD}{Colors.MAGENTA}[*] Interesting Constraints (sample):{Colors.END}")
            for ci in self.constraints_found[:3]:
                print(f"    Address: {ci['address']}")
                print(f"    Number of constraints: {ci['num_constraints']}")
                for c in ci['constraints']:
                    print(f"      - {c[:80]}...")
            print()
        if self.unconstrained_paths:
            print(f"{Colors.BOLD}{Colors.RED}[!!!] CRITICAL: Unconstrained Execution Paths Found!{Colors.END}")
            print(f"      This may allow arbitrary code execution")
            print(f"      Affected states: {len(self.unconstrained_paths)}\n")

    def export_results(self, output_file):
        results = {
            'binary': self.binary_path, 'binary_name': os.path.basename(self.binary_path), 'binary_size': None,
            'timestamp': datetime.now().isoformat(), 'statistics': self.stats,
            'vulnerabilities': dict(self.vulnerabilities), 'dangerous_functions': self.dangerous_functions,
            'anti_analysis': self.anti_analysis_detected,
            'taint_analysis': {
                'sinks_found': len(self.taint_sinks),
                'tainted_sinks': [{
                    'address': s.get('address'), 'function': s.get('function'),
                    'type': s.get('vulnerability_type'), 'tainted_args': s.get('tainted_arguments'),
                    'exploit_hex': s.get('exploit_input', b'').hex() if s.get('exploit_input') else None
                } for s in self.taint_sinks],
                'data_flows': self.data_flows, 'taint_sources': list(self.taint_sources)
            },
            'exploit_candidates': [{
                'target_function': e.get('target_function'), 'address': e.get('address'),
                'category': e.get('category'), 'input_hex': e.get('input').hex() if e.get('input') else None,
                'description': e.get('description')
            } for e in self.exploit_candidates],
            'constraints_sample': self.constraints_found[:10],
            'coverage': {
                'percentage': self.stats.get('code_coverage',0), 'addresses_hit': len(self.coverage_info),
                'total_blocks': self.stats.get('basic_blocks',0)
            }
        }
        try: results['binary_size'] = os.path.getsize(self.binary_path)
        except Exception: results['binary_size'] = None
        outdir = os.path.dirname(output_file) or '.'
        try: os.makedirs(outdir, exist_ok=True)
        except Exception: pass
        try:
            with open(output_file, 'w') as f: json.dump(results, f, indent=2, default=str)
            print(f"{Colors.GREEN}[+] Results exported to: {output_file}{Colors.END}")
        except Exception as e:
            print(f"{Colors.RED}[!] Failed to write results to {output_file}: {e}{Colors.END}")
        return results

    def generate_poc_script(self, output_file):
        if not self.exploit_candidates:
            print(f"{Colors.YELLOW}[!] No exploit candidates to generate PoC{Colors.END}"); return
        poc = f'''#!/usr/bin/env python3
"""
Proof of Concept Exploit Script
Generated by SymbolicHunter
Target: {self.binary_path}
Generated: {datetime.now().isoformat()}

WARNING: Use only for authorized security testing!
"""

import subprocess, sys

def test_exploit(name, data, desc):
    print(f"[*] Testing: {{name}}")
    print(f"    {{desc}}")
    print(f"    Input length: {{len(data)}} bytes")
    try:
        with open('exploit_input.bin','wb') as f: f.write(data)
        r = subprocess.run(['{self.binary_path}'], stdin=open('exploit_input.bin','rb'),
                           capture_output=True, timeout=5)
        print(f"    Return code: {{r.returncode}}")
        if r.stdout: print(f"    Stdout: {{r.stdout[:100]}}")
        if r.stderr: print(f"    Stderr: {{r.stderr[:100]}}")
        print()
    except subprocess.TimeoutExpired:
        print("    [!] Process timeout")
    except Exception as e:
        print(f"    [!] Error: {{e}}")
    print()

def main():
    print("="*60); print("SymbolicHunter - Exploit PoC Script"); print("="*60); print()
'''
        for i, ex in enumerate(self.exploit_candidates[:10],1):
            poc += f'''    test_exploit("{ex.get('target_function')}",
                  bytes.fromhex("{ex.get('input').hex() if ex.get('input') else ''}"),
                  "{ex.get('description')}")\n'''
        poc += '''    print("[*] All exploit tests completed")\n\nif __name__ == '__main__':\n    main()\n'''
        try:
            with open(output_file,'w') as f: f.write(poc)
            import stat; os.chmod(output_file, os.stat(output_file).st_mode | stat.S_IEXEC)
            print(f"{Colors.GREEN}[+] PoC script generated: {output_file}{Colors.END}")
            print(f"    Run with: python3 {output_file}")
        except Exception as e:
            print(f"{Colors.RED}[!] Failed to write PoC script: {e}{Colors.END}")

# ===========================
# CLI: file or directory mode
# ===========================
def _int_auto(x: str) -> int:
    return int(x, 0)  # supports "0x..." or decimal

def main():
    p = argparse.ArgumentParser(
        description='SymbolicHunter - Comprehensive symbolic execution analysis tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s vulnerable_binary
  %(prog)s --timeout 600 --output results.json binary
  %(prog)s --recursive /path/to/dir
  %(prog)s --recursive --all /path/to/dir
  %(prog)s --blob-arch aarch64 --blob-base 0x10000000 /weird/firmware.bin
        """
    )
    p.add_argument('binary', nargs='?', help='Path to the binary file OR directory')
    p.add_argument('extra_binary', nargs='?', help=argparse.SUPPRESS)
    p.add_argument('-v','--verbose', action='store_true', help='Enable verbose output')
    p.add_argument('--max-states', type=int, default=1000, help='Maximum number of states to explore')
    p.add_argument('--timeout', type=int, default=300, help='Analysis timeout in seconds')
    p.add_argument('-o','--output', help='File path (single file) or base directory (folder mode)')
    p.add_argument('--poc', help='Generate PoC exploit script (per-file in folder mode)')
    p.add_argument('--find-function', help='Find paths to specific function (by name)')
    p.add_argument('--recursive', action='store_true', default=False, help='Recursively walk directories')
    p.add_argument('--all', action='store_true', default=False, help='Try ANY non-text file type (use with care)')

    # loader/verbosity knobs
    p.add_argument('--no-blob-fallback', dest='blob_fallback', action='store_false',
                   help='Disable Blob backend fallback for unknown binaries (default: enabled)')
    p.set_defaults(blob_fallback=True)
    p.add_argument('--blob-arch', default='amd64', help='Blob arch (amd64, i386, arm, aarch64, mips, etc.)')
    p.add_argument('--blob-base', type=_int_auto, default='0x400000', help='Blob base address (int or 0xHEX)')
    p.add_argument('--blob-entry', type=_int_auto, default=None, help='Blob entry point override (int or 0xHEX)')
    p.add_argument('--no-quiet-claripy', dest='quiet_claripy', action='store_false',
                   help='Show claripy warnings (default: hidden unless -v)')
    p.set_defaults(quiet_claripy=True)

    args = p.parse_args()

    # legacy quirk handling
    if args.extra_binary and not args.binary: args.binary = args.extra_binary
    elif args.extra_binary and args.binary: args.binary = args.extra_binary
    if not args.binary:
        p.error("binary path or directory is required"); sys.exit(1)

    path = Path(args.binary).expanduser().resolve()

    # -------- Directory mode --------
    if path.is_dir():
        candidates = collect_candidate_files(path, recursive=args.recursive, include_all=args.all)
        if not candidates:
            print(f"{Colors.YELLOW}[!] No candidate files found in {path} (use --all to force more){Colors.END}")
            sys.exit(2)
        print(f"{Colors.CYAN}[*] Found {len(candidates)} candidate files to analyze{Colors.END}")

        # base output directory
        if args.output:
            out_base = Path(args.output).expanduser()
            base_outdir = out_base if (not out_base.suffix or str(args.output).endswith(os.sep)) else out_base.parent
        else:
            base_outdir = Path.cwd() / "sh_reports"
        base_outdir.mkdir(parents=True, exist_ok=True)

        failures: List[str] = []
        for idx, cand in enumerate(candidates, 1):
            print(f"\n{Colors.BOLD}{Colors.BLUE}[{idx}/{len(candidates)}] Analyzing: {cand}{Colors.END}")
            kind = guess_file_kind(cand)
            if kind in {"TEXT","SCRIPT"} and not args.all:
                print(f"{Colors.YELLOW}[!] Skipping non-binary file (use --all to force): {cand}{Colors.END}")
                continue
            try:
                hunter = SymbolicHunter(
                    str(cand), verbose=args.verbose, max_states=args.max_states, timeout=args.timeout,
                    blob_fallback=args.blob_fallback, blob_arch=args.blob_arch,
                    blob_base=args.blob_base, blob_entry=args.blob_entry, quiet_claripy=args.quiet_claripy
                )
                hunter.print_header(); hunter.explore_binary(target_function=args.find_function); hunter.print_results()

                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                per_out = base_outdir / f"{cand.stem}_{ts}"; per_out.mkdir(parents=True, exist_ok=True)

                # JSON
                results = hunter.export_results(str(per_out / "results.json"))

                # HTML (if reporting module is available)
                try:
                    from modules.reporting import generate_report
                    html_path = generate_report(results, outdir=str(per_out), title=f"SymbolicHunter Report - {cand.name}")
                    print(f"{Colors.GREEN}[+] HTML report for {cand.name}: {html_path}{Colors.END}")
                except Exception as e:
                    print(f"{Colors.YELLOW}[!] HTML report skipped for {cand.name}: {e}{Colors.END}")
                    if args.verbose:
                        import traceback; traceback.print_exc()

                # NEW: signatures (YARA, Suricata, Sigma, IOC text)
                sig_dir = per_out / "signatures"
                generate_signature_bundle(cand, results, sig_dir)

                if args.poc:
                    poc_target = per_out / ("poc_test.py" if (args.poc.endswith(os.sep) or Path(args.poc).is_dir()) else Path(args.poc).name)
                    hunter.generate_poc_script(str(poc_target))

            except Exception as e:
                print(f"{Colors.RED}[!] Failed to analyze {cand}: {e}{Colors.END}")
                if args.verbose:
                    import traceback; traceback.print_exc()
                failures.append(str(cand)); continue

        if failures:
            print(f"\n{Colors.YELLOW}[!] Some files failed to analyze:{Colors.END}")
            for f in failures: print(f"   - {f}")
            sys.exit(3 if len(failures)==len(candidates) else 0)
        else:
            print(f"\n{Colors.GREEN}[+] All files processed successfully{Colors.END}")
            sys.exit(0)

    # -------- Single file mode --------
    if path.is_file():
        kind = guess_file_kind(path)
        if kind in {"TEXT","SCRIPT"} and not args.all:
            print(f"{Colors.YELLOW}[!] This looks like a text/script file. Use --all to force or select a binary.{Colors.END}")
            sys.exit(5)
        try:
            hunter = SymbolicHunter(
                str(path), verbose=args.verbose, max_states=args.max_states, timeout=args.timeout,
                blob_fallback=args.blob_fallback, blob_arch=args.blob_arch,
                blob_base=args.blob_base, blob_entry=args.blob_entry, quiet_claripy=args.quiet_claripy
            )
            hunter.print_header(); hunter.explore_binary(target_function=args.find_function); hunter.print_results()

            # determine where to put results + signatures
            if args.output:
                outdir = (Path(args.output).parent if Path(args.output).suffix else Path(args.output))
            else:
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                outdir = Path.cwd() / "sh_reports" / f"{path.stem}_{ts}"
            outdir.mkdir(parents=True, exist_ok=True)

            # always export results here
            results_path = outdir / ("results.json" if not (Path(args.output).suffix if args.output else False) else Path(args.output).name)
            results = hunter.export_results(str(results_path))

            # HTML if module exists
            try:
                from modules.reporting import generate_report
                html_path = generate_report(results, outdir=str(outdir), title=f"SymbolicHunter Report - {path.name}")
                print(f"{Colors.GREEN}[+] HTML report generated: {html_path}{Colors.END}")
            except Exception as e:
                print(f"{Colors.YELLOW}[!] HTML report generation skipped: {e}{Colors.END}")
                if args.verbose:
                    import traceback; traceback.print_exc()

            # NEW: signatures
            sig_dir = outdir / "signatures"
            generate_signature_bundle(path, results, sig_dir)

            if args.poc: hunter.generate_poc_script(str(outdir / ("poc_test.py" if Path(args.poc).is_dir() else Path(args.poc).name)))
            sys.exit(0 if sum(len(v) for v in hunter.vulnerabilities.values()) == 0 else 1)

        except Exception as e:
            print(f"{Colors.RED}[!] Failed to analyze {path}: {e}{Colors.END}")
            if args.verbose:
                import traceback; traceback.print_exc()
            sys.exit(4)

    p.error("Unsupported path type"); sys.exit(1)

if __name__ == '__main__':
    main()

