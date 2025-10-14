#!/usr/bin/env python3
"""
SymbolicHunter - Comprehensive Symbolic Execution Analysis Tool
Automatically detects vulnerabilities and analyzes binaries using angr
"""

import angr
import claripy
import sys
import argparse
from collections import defaultdict
import logging
from datetime import datetime
import json

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

class SymbolicHunter:
    def __init__(self, binary_path, verbose=False, max_states=1000, timeout=300):
        self.binary_path = binary_path
        self.verbose = verbose
        self.max_states = max_states
        self.timeout = timeout

        # Results storage
        self.vulnerabilities = defaultdict(list)
        self.interesting_paths = []
        self.constraints_found = []
        self.unconstrained_paths = []
        self.dangerous_functions = []
        self.cfg = None
        self.functions_found = []
        self.winning_inputs = []  # Inputs that reach interesting locations
        self.coverage_info = set()  # Track code coverage
        self.anti_analysis_detected = []  # Anti-debugging/anti-analysis techniques
        self.exploit_candidates = []  # Potential exploits with PoC inputs
        self.unique_vulns = {}  # Deduplicated vulnerabilities

        # Statistics
        self.stats = {
            'paths_explored': 0,
            'states_analyzed': 0,
            'constraints_solved': 0,
            'time_elapsed': 0,
            'functions_discovered': 0,
            'basic_blocks': 0,
            'code_coverage': 0
        }

        # Setup logging
        if verbose:
            logging.getLogger('angr').setLevel(logging.INFO)
        else:
            logging.getLogger('angr').setLevel(logging.WARNING)

        print(f"{Colors.BOLD}{Colors.CYAN}[*] Loading binary: {binary_path}{Colors.END}")

        # Load the binary with angr
        try:
            self.project = angr.Project(binary_path, auto_load_libs=False)
            print(f"{Colors.GREEN}[+] Binary loaded successfully{Colors.END}")
            print(f"    Architecture: {self.project.arch.name}")
            print(f"    Entry point: {hex(self.project.entry)}")
            print(f"    Base address: {hex(self.project.loader.main_object.min_addr)}")

            # Perform initial CFG analysis with angr
            print(f"\n{Colors.CYAN}[*] Performing CFG analysis...{Colors.END}")
            try:
                self.cfg = self.project.analyses.CFGFast()
                self.stats['functions_discovered'] = len(self.cfg.functions)
                self.stats['basic_blocks'] = len(list(self.cfg.graph.nodes()))
                print(f"{Colors.GREEN}[+] CFG analysis complete{Colors.END}")
                print(f"    Functions discovered: {self.stats['functions_discovered']}")
                print(f"    Basic blocks: {self.stats['basic_blocks']}")

                # Identify dangerous functions using angr's knowledge base
                self.identify_dangerous_functions()

            except Exception as e:
                print(f"{Colors.YELLOW}[!] CFG analysis failed: {e}{Colors.END}")
                if self.verbose:
                    import traceback
                    traceback.print_exc()

        except Exception as e:
            print(f"{Colors.RED}[!] Failed to load binary: {e}{Colors.END}")
            sys.exit(1)

    def print_header(self):
        """Print tool header"""
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
        """Identify dangerous API calls using angr CFG"""
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

            # Check each category
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

                        # Flag anti-analysis techniques
                        if category in ['anti_debug', 'anti_vm']:
                            self.anti_analysis_detected.append({
                                'technique': category,
                                'function': func_name,
                                'address': hex(func_addr)
                            })

        if self.dangerous_functions:
            print(f"{Colors.YELLOW}[!] Found {len(self.dangerous_functions)} dangerous API calls{Colors.END}")

            # Show summary by category
            for category, funcs in api_categories.items():
                color = Colors.RED if category in ['process', 'anti_debug', 'anti_vm'] else Colors.YELLOW
                print(f"    {color}[{category.upper()}]{Colors.END} {len(funcs)} calls")

            if self.verbose:
                for func in self.dangerous_functions[:10]:
                    print(f"    - {func['name']} at {func['address']}")
        else:
            print(f"{Colors.GREEN}[+] No known dangerous APIs detected{Colors.END}")

        # Warn about anti-analysis
        if self.anti_analysis_detected:
            print(f"\n{Colors.RED}[!!!] Anti-Analysis Techniques Detected!{Colors.END}")
            print(f"      This binary may evade debugging/analysis")
            for tech in self.anti_analysis_detected:
                print(f"      - {tech['technique']}: {tech['function']} at {tech['address']}")

    def check_buffer_overflow(self, state):
        """Detect potential buffer overflow vulnerabilities"""
        try:
            # Check for symbolic memory operations that could overflow
            # Look at symbolic registers that might be used for memory access
            if self.project.arch.name == 'AMD64':
                regs_to_check = [state.regs.rax, state.regs.rbx, state.regs.rcx, 
                                state.regs.rdx, state.regs.rsi, state.regs.rdi]
            else:
                regs_to_check = [state.regs.eax, state.regs.ebx, state.regs.ecx, 
                                state.regs.edx, state.regs.esi, state.regs.edi]

            for reg in regs_to_check:
                if reg.symbolic:
                    # Check if this could point to a large memory address (overflow)
                    if state.solver.satisfiable(extra_constraints=[reg > 0x7fff0000]):
                        self.vulnerabilities['buffer_overflow'].append({
                            'address': hex(state.addr),
                            'register': str(reg),
                            'description': 'Symbolic pointer could overflow buffer bounds'
                        })
                        break  # Only report once per state
        except Exception as e:
            if self.verbose:
                print(f"    Buffer overflow check error: {e}")

    def check_integer_overflow(self, state):
        """Detect potential integer overflow vulnerabilities"""
        try:
            # Look for arithmetic operations on symbolic values
            for var in state.solver.get_variables('file_/dev/stdin'):
                # Check if we can make this overflow
                if state.solver.satisfiable(extra_constraints=[var > 0x7fffffff]):
                    self.vulnerabilities['integer_overflow'].append({
                        'address': hex(state.addr),
                        'variable': str(var),
                        'description': 'Symbolic integer can overflow'
                    })
        except Exception as e:
            if self.verbose:
                print(f"    Integer overflow check error: {e}")

    def check_format_string(self, state):
        """Detect format string vulnerabilities"""
        try:
            # Check if we're at a printf-like function with symbolic format string
            ip = state.addr
            block = self.project.factory.block(ip)

            # Look for calls to printf, sprintf, etc.
            dangerous_funcs = ['printf', 'sprintf', 'fprintf', 'snprintf']

            for insn in block.capstone.insns:
                if insn.mnemonic == 'call':
                    # Check if format argument is symbolic
                    if self.project.arch.name == 'AMD64':
                        fmt_arg = state.regs.rsi  # Second argument in x64
                    else:
                        fmt_arg = state.regs.esi

                    if fmt_arg.symbolic:
                        self.vulnerabilities['format_string'].append({
                            'address': hex(state.addr),
                            'description': 'Symbolic format string argument'
                        })
        except Exception as e:
            if self.verbose:
                print(f"    Format string check error: {e}")

    def check_null_deref(self, state):
        """Detect NULL pointer dereference"""
        try:
            # Check for symbolic pointers that could be NULL
            if self.project.arch.name == 'AMD64':
                regs_to_check = [state.regs.rax, state.regs.rbx, state.regs.rcx, 
                                state.regs.rdx, state.regs.rsi, state.regs.rdi]
            else:
                regs_to_check = [state.regs.eax, state.regs.ebx, state.regs.ecx, state.regs.edx]

            for reg in regs_to_check:
                if reg.symbolic and state.solver.satisfiable(extra_constraints=[reg == 0]):
                    self.vulnerabilities['null_deref'].append({
                        'address': hex(state.addr),
                        'register': str(reg),
                        'description': 'Register can be NULL and may be dereferenced'
                    })
        except Exception as e:
            if self.verbose:
                print(f"    NULL deref check error: {e}")

    def check_division_by_zero(self, state):
        """Detect division by zero"""
        try:
            ip = state.addr
            block = self.project.factory.block(ip)

            for insn in block.capstone.insns:
                if insn.mnemonic in ['div', 'idiv']:
                    # Check if divisor can be zero
                    if self.project.arch.name == 'AMD64':
                        divisor = state.regs.rcx
                    else:
                        divisor = state.regs.ecx

                    if divisor.symbolic and state.solver.satisfiable(extra_constraints=[divisor == 0]):
                        self.vulnerabilities['div_by_zero'].append({
                            'address': hex(state.addr),
                            'description': 'Division by zero possible'
                        })
        except Exception as e:
            if self.verbose:
                print(f"    Division by zero check error: {e}")

    def check_unconstrained(self, state):
        """Detect unconstrained execution (potential code execution)"""
        try:
            if state.regs.ip.symbolic:
                # Instruction pointer is symbolic - critical vulnerability
                self.vulnerabilities['unconstrained_execution'].append({
                    'address': hex(state.addr),
                    'description': 'Instruction pointer is symbolic - possible code execution',
                    'severity': 'CRITICAL'
                })
                self.unconstrained_paths.append(state)
        except Exception as e:
            if self.verbose:
                print(f"    Unconstrained check error: {e}")

    def analyze_state(self, state):
        """Run all vulnerability checks on a state"""
        self.stats['states_analyzed'] += 1

        # Track code coverage
        self.coverage_info.add(state.addr)

        # Run all checks (with deduplication)
        addr_key = state.addr

        # Only check each address once to reduce noise
        if addr_key not in self.unique_vulns:
            self.unique_vulns[addr_key] = True

            self.check_buffer_overflow(state)
            self.check_integer_overflow(state)
            self.check_format_string(state)
            self.check_null_deref(state)
            self.check_division_by_zero(state)
            self.check_unconstrained(state)

        # Check if we reached a dangerous function
        for dangerous in self.dangerous_functions:
            if state.addr == int(dangerous['address'], 16):
                try:
                    # Try to generate input that reaches this dangerous function
                    if state.solver.satisfiable():
                        stdin_vars = [v for v in state.solver.get_variables() if 'stdin' in str(v)]
                        if stdin_vars:
                            concrete_input = state.solver.eval(stdin_vars[0], cast_to=bytes)
                            self.exploit_candidates.append({
                                'target_function': dangerous['name'],
                                'address': dangerous['address'],
                                'category': dangerous.get('category', 'unknown'),
                                'input': concrete_input[:100],
                                'description': f"Input reaches {dangerous['name']} - potential exploit vector"
                            })
                except:
                    pass

        # Try to generate concrete input for interesting states
        if len(state.solver.constraints) > 5:  # Has interesting constraints
            try:
                # Attempt to solve for a concrete input
                stdin_vars = [v for v in state.solver.get_variables() if 'stdin' in str(v)]
                if stdin_vars and state.solver.satisfiable():
                    # Get a concrete value for stdin
                    concrete_stdin = state.solver.eval(stdin_vars[0], cast_to=bytes)
                    self.winning_inputs.append({
                        'address': hex(state.addr),
                        'input': concrete_stdin[:50],  # First 50 bytes
                        'num_constraints': len(state.solver.constraints)
                    })
            except:
                pass

        # Store interesting constraints (sample only)
        if len(state.solver.constraints) > 0 and len(self.constraints_found) < 100:
            self.constraints_found.append({
                'address': hex(state.addr),
                'num_constraints': len(state.solver.constraints),
                'constraints': [str(c) for c in list(state.solver.constraints)[:3]]  # First 3
            })

    def explore_binary(self):
        """Main exploration routine using angr simulation manager"""
        print(f"\n{Colors.BOLD}{Colors.YELLOW}[*] Starting symbolic execution with angr...{Colors.END}")
        print(f"    Max states: {self.max_states}")
        print(f"    Timeout: {self.timeout}s\n")

        # Create initial state with symbolic stdin using angr - simplified approach
        state = self.project.factory.entry_state(
            add_options={
                angr.options.LAZY_SOLVES,
            }
        )

        # Make stdin symbolic with angr's claripy - using correct SimFile API
        stdin_size = 200  # bytes of symbolic input
        stdin_data = claripy.BVS('stdin', 8 * stdin_size)

        # Create a proper SimFile for stdin
        stdin_file = angr.storage.SimFile('stdin', content=stdin_data, size=stdin_size)

        # Replace stdin with our symbolic file
        state.fs.insert('stdin', stdin_file)
        state.posix.stdin = stdin_file

        # Add symbolic command line arguments if not Windows
        if self.project.loader.main_object.os != 'windows':
            arg1 = claripy.BVS('arg1', 8 * 100)
            state.posix.argv = [self.project.filename, arg1]
        else:
            print(f"{Colors.CYAN}[*] Detected Windows PE binary{Colors.END}")

        # Create angr simulation manager with exploration techniques
        simgr = self.project.factory.simulation_manager(state)

        # Add exploration technique to prioritize dangerous functions
        if self.dangerous_functions:
            dangerous_addrs = [int(f['address'], 16) for f in self.dangerous_functions]
            print(f"{Colors.CYAN}[*] Prioritizing {len(dangerous_addrs)} dangerous functions{Colors.END}")

            # Use DFS to explore deeper and find functions
            try:
                from angr.exploration_techniques import DFS
                simgr.use_technique(DFS())
            except:
                pass

        print(f"{Colors.CYAN}[*] Using angr exploration strategies...{Colors.END}\n")

        start_time = datetime.now()
        step_count = 0

        try:
            while len(simgr.active) > 0 and step_count < self.max_states:

                # Step through execution using angr
                simgr.step()
                step_count += 1
                self.stats['paths_explored'] = len(simgr.active) + len(simgr.deadended)

                # Analyze each active state with angr
                for state in simgr.active:
                    self.analyze_state(state)

                # Check deadended states (paths that terminated)
                for state in simgr.deadended:
                    self.analyze_state(state)

                # Handle errored states (paths that crashed - potentially vulnerable!)
                for errored_state in simgr.errored:
                    if hasattr(errored_state, 'state'):
                        self.vulnerabilities['crashed_paths'].append({
                            'address': hex(errored_state.state.addr),
                            'error': str(errored_state.error)[:200],
                            'description': 'Path resulted in error - possible vulnerability'
                        })

                # Progress update
                if step_count % 50 == 0:
                    elapsed = (datetime.now() - start_time).total_seconds()
                    active = len(simgr.active)
                    dead = len(simgr.deadended)
                    errors = len(simgr.errored)
                    uncon = len(simgr.unconstrained)

                    print(f"{Colors.CYAN}[*] Step {step_count}: "
                          f"Active={active}, Dead={dead}, Error={errors}, Uncon={uncon}, "
                          f"Exploits={len(self.exploit_candidates)}, Time={elapsed:.1f}s{Colors.END}")

                # Timeout check
                if (datetime.now() - start_time).total_seconds() > self.timeout:
                    print(f"\n{Colors.YELLOW}[!] Timeout reached{Colors.END}")
                    break

                # Prune if too many states (angr memory management)
                if len(simgr.active) > 100:
                    print(f"{Colors.YELLOW}[!] Pruning states (too many active paths){Colors.END}")
                    # Keep only the first 50 states
                    simgr.active = simgr.active[:50]

        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[!] Analysis interrupted by user{Colors.END}")
        except Exception as e:
            print(f"\n{Colors.RED}[!] Analysis error: {e}{Colors.END}")
            if self.verbose:
                import traceback
                traceback.print_exc()

        self.stats['time_elapsed'] = (datetime.now() - start_time).total_seconds()

        # Calculate code coverage
        if self.stats['basic_blocks'] > 0:
            self.stats['code_coverage'] = (len(self.coverage_info) / self.stats['basic_blocks']) * 100

        # Final sweep - analyze all remaining states in all stashes
        print(f"\n{Colors.CYAN}[*] Performing final analysis of all paths...{Colors.END}")

        for stash_name in ['active', 'deadended', 'errored', 'unconstrained']:
            stash = getattr(simgr, stash_name, [])
            for item in stash:
                # Handle errored states differently
                if stash_name == 'errored':
                    if hasattr(item, 'state'):
                        self.analyze_state(item.state)
                else:
                    self.analyze_state(item)

        self.stats['states_analyzed'] = len(simgr.deadended) + len(simgr.active)

    def print_results(self):
        """Print comprehensive analysis results"""
        print(f"\n{Colors.BOLD}{Colors.GREEN}╔════════════════════════════════════════════════════════╗")
        print(f"║                  ANALYSIS COMPLETE                     ║")
        print(f"╚════════════════════════════════════════════════════════╝{Colors.END}\n")

        # Statistics
        print(f"{Colors.BOLD}{Colors.CYAN}[*] Execution Statistics:{Colors.END}")
        print(f"    Paths explored: {self.stats['paths_explored']}")
        print(f"    States analyzed: {self.stats['states_analyzed']}")
        print(f"    Time elapsed: {self.stats['time_elapsed']:.2f}s")
        print(f"    Constraints found: {len(self.constraints_found)}")

        # Vulnerability summary
        total_vulns = sum(len(v) for v in self.vulnerabilities.values())
        print(f"\n{Colors.BOLD}{Colors.YELLOW}[*] Vulnerability Summary:{Colors.END}")
        print(f"    Total issues found: {total_vulns}\n")

        # Detailed vulnerabilities
        if total_vulns > 0:
            for vuln_type, instances in self.vulnerabilities.items():
                if instances:
                    severity_color = Colors.RED if vuln_type == 'unconstrained_execution' else Colors.YELLOW
                    print(f"{Colors.BOLD}{severity_color}[!] {vuln_type.upper().replace('_', ' ')} "
                          f"({len(instances)} found):{Colors.END}")

                    for idx, vuln in enumerate(instances[:5], 1):  # Show first 5
                        print(f"    {idx}. Address: {vuln.get('address', 'N/A')}")
                        print(f"       {vuln.get('description', 'No description')}")
                        if 'severity' in vuln:
                            print(f"       Severity: {Colors.RED}{vuln['severity']}{Colors.END}")

                    if len(instances) > 5:
                        print(f"    ... and {len(instances) - 5} more")
                    print()
        else:
            print(f"    {Colors.GREEN}No vulnerabilities detected{Colors.END}\n")

        # Interesting constraints
        if self.constraints_found and self.verbose:
            print(f"{Colors.BOLD}{Colors.MAGENTA}[*] Interesting Constraints (sample):{Colors.END}")
            for constraint_info in self.constraints_found[:3]:
                print(f"    Address: {constraint_info['address']}")
                print(f"    Number of constraints: {constraint_info['num_constraints']}")
                for c in constraint_info['constraints']:
                    print(f"      - {c[:80]}...")
            print()

        # Unconstrained paths (most critical)
        if self.unconstrained_paths:
            print(f"{Colors.BOLD}{Colors.RED}[!!!] CRITICAL: Unconstrained Execution Paths Found!{Colors.END}")
            print(f"      This may allow arbitrary code execution")
            print(f"      Affected states: {len(self.unconstrained_paths)}\n")

    def export_results(self, output_file):
        """Export results to JSON"""
        results = {
            'binary': self.binary_path,
            'timestamp': datetime.now().isoformat(),
            'statistics': self.stats,
            'vulnerabilities': dict(self.vulnerabilities),
            'dangerous_functions': self.dangerous_functions,
            'anti_analysis': self.anti_analysis_detected,
            'exploit_candidates': [
                {
                    'target_function': e['target_function'],
                    'address': e['address'],
                    'category': e['category'],
                    'input_hex': e['input'].hex(),
                    'description': e['description']
                } for e in self.exploit_candidates
            ],
            'constraints_sample': self.constraints_found[:10],
            'coverage': {
                'percentage': self.stats['code_coverage'],
                'addresses_hit': len(self.coverage_info),
                'total_blocks': self.stats['basic_blocks']
            }
        }

        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)

        print(f"{Colors.GREEN}[+] Results exported to: {output_file}{Colors.END}")

    def generate_poc_script(self, output_file):
        """Generate a Python PoC script for testing exploits"""
        if not self.exploit_candidates:
            print(f"{Colors.YELLOW}[!] No exploit candidates to generate PoC{Colors.END}")
            return

        poc_script = f'''#!/usr/bin/env python3
"""
Proof of Concept Exploit Script
Generated by SymbolicHunter
Target: {self.binary_path}
Generated: {datetime.now().isoformat()}

WARNING: Use only for authorized security testing!
"""

import subprocess
import sys

def test_exploit(exploit_name, input_data, description):
    """Test an exploit candidate"""
    print(f"[*] Testing: {{exploit_name}}")
    print(f"    {{description}}")
    print(f"    Input length: {{len(input_data)}} bytes")

    try:
        # Write input to file
        with open('exploit_input.bin', 'wb') as f:
            f.write(input_data)

        # Run the target with the exploit input
        # Adjust this command based on how the binary accepts input
        result = subprocess.run(
            ['{self.binary_path}'],
            stdin=open('exploit_input.bin', 'rb'),
            capture_output=True,
            timeout=5
        )

        print(f"    Return code: {{result.returncode}}")
        if result.stdout:
            print(f"    Stdout: {{result.stdout[:100]}}")
        if result.stderr:
            print(f"    Stderr: {{result.stderr[:100]}}")
        print()

    except subprocess.TimeoutExpired:
        print(f"    [!] Process timeout - possible infinite loop or hang")
    except Exception as e:
        print(f"    [!] Error: {{e}}")
    print()

def main():
    """Main exploit testing routine"""
    print("="*60)
    print("SymbolicHunter - Exploit PoC Script")
    print("="*60)
    print()

'''

        # Add each exploit candidate
        for idx, exploit in enumerate(self.exploit_candidates[:10], 1):
            poc_script += f'''    # Exploit {idx}: {exploit['target_function']}
    test_exploit(
        exploit_name="{exploit['target_function']}",
        input_data=bytes.fromhex("{exploit['input'].hex()}"),
        description="{exploit['description']}"
    )

'''

        poc_script += '''    print("[*] All exploit tests completed")

if __name__ == '__main__':
    main()
'''

        with open(output_file, 'w') as f:
            f.write(poc_script)

        # Make executable on Unix
        import os
        import stat
        os.chmod(output_file, os.stat(output_file).st_mode | stat.S_IEXEC)

        print(f"{Colors.GREEN}[+] PoC script generated: {output_file}{Colors.END}")
        print(f"    Run with: python3 {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description='SymbolicHunter - Comprehensive symbolic execution analysis tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s vulnerable_binary
  %(prog)s -v --max-states 2000 binary
  %(prog)s --timeout 600 --output results.json binary
        """
    )

    parser.add_argument('binary', nargs='?', help='Path to the binary to analyze')
    parser.add_argument('extra_binary', nargs='?', help=argparse.SUPPRESS)
    parser.add_argument('-v', '--verbose', action='store_true', 
                       help='Enable verbose output')
    parser.add_argument('--max-states', type=int, default=1000,
                       help='Maximum number of states to explore (default: 1000)')
    parser.add_argument('--timeout', type=int, default=300,
                       help='Analysis timeout in seconds (default: 300)')
    parser.add_argument('-o', '--output', help='Export results to JSON file')
    parser.add_argument('--poc', help='Generate PoC exploit script')
    parser.add_argument('--find-function', help='Find paths to specific function (by name)')

    args = parser.parse_args()

    # Handle the case where binary might be in extra_binary due to flags
    if args.extra_binary and not args.binary:
        args.binary = args.extra_binary
    elif args.extra_binary and args.binary:
        # User likely put flags after binary name
        args.binary = args.extra_binary

    if not args.binary:
        parser.error("binary path is required")
        sys.exit(1)

    # Create hunter instance
    hunter = SymbolicHunter(
        args.binary,
        verbose=args.verbose,
        max_states=args.max_states,
        timeout=args.timeout
    )

    # Print header
    hunter.print_header()

    # Run analysis
    hunter.explore_binary()

    # Print results
    hunter.print_results()

    # Export if requested
    if args.output:
        hunter.export_results(args.output)

    # Generate PoC if requested
    if args.poc:
        hunter.generate_poc_script(args.poc)

    # Summary
    print(f"\n{Colors.BOLD}{Colors.CYAN}[*] Analysis Summary:{Colors.END}")
    total_vulns = sum(len(v) for v in hunter.vulnerabilities.values())
    if total_vulns > 0:
        print(f"    {Colors.RED}⚠ Found {total_vulns} potential security issues{Colors.END}")
    else:
        print(f"    {Colors.GREEN}✓ No obvious vulnerabilities detected{Colors.END}")

    if hunter.exploit_candidates:
        print(f"    {Colors.MAGENTA}🎯 Generated {len(hunter.exploit_candidates)} exploit candidates{Colors.END}")

    if hunter.anti_analysis_detected:
        print(f"    {Colors.RED}🛡 Binary uses anti-analysis techniques{Colors.END}")

    print()

    # Exit with appropriate code
    sys.exit(0 if total_vulns == 0 else 1)


if __name__ == '__main__':
    main()
