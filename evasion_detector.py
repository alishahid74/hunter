#!/usr/bin/env python3
"""
AVSU/AVIZO Evasion Detection & Mitigation Tool
Identifies and disables evasive techniques using angr binary analysis
"""

import angr
import claripy
import json
import time
import threading
import logging
from datetime import datetime
from collections import defaultdict
from pathlib import Path
import argparse
import sys

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class EvasionDetector:
    """Core detection engine for evasive techniques"""

    def __init__(self, binary_path, enable_mitigation=True):
        self.binary_path = binary_path
        self.enable_mitigation = enable_mitigation
        self.detections = defaultdict(list)
        self.project = None
        self.cfg = None

        # Evasion technique signatures
        self.signatures = {
            'process_injection': [
                'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread',
                'NtCreateThreadEx', 'RtlCreateUserThread', 'QueueUserAPC'
            ],
            'process_hollowing': [
                'NtUnmapViewOfSection', 'VirtualAllocEx', 'WriteProcessMemory',
                'SetThreadContext', 'ResumeThread', 'ZwUnmapViewOfSection'
            ],
            'anti_debugging': [
                'IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'NtQueryInformationProcess',
                'OutputDebugString', 'ptrace', 'DebugActiveProcess'
            ],
            'anti_vm': [
                'cpuid', 'rdtsc', 'in ', 'vmware', 'vbox', 'qemu',
                'VIRTUAL', 'VMware', 'VBoxGuest', 'vm_', 'hypervisor'
            ],
            'anti_sandbox': [
                'GetTickCount', 'Sleep', 'GetSystemTime', 'NtDelayExecution',
                'mouse_event', 'GetCursorPos', 'GetForegroundWindow', 'GetLastInputInfo'
            ],
            'code_injection': [
                'SetWindowsHookEx', 'CallNextHookEx', 'LoadLibrary',
                'GetProcAddress', 'VirtualProtect', 'mprotect', 'dlsym'
            ]
        }

        # Whitelist common benign functions
        self.whitelist = {
            '__libc_start_main', 'printf', 'scanf', 'puts', 'malloc', 'free',
            'strcpy', 'strcmp', 'strlen', 'memcpy', 'memset', 'exit',
            'fopen', 'fclose', 'fread', 'fwrite', 'fprintf', 'sprintf'
        }

    def load_binary(self):
        """Load binary into angr for analysis"""
        try:
            logger.info(f"Loading binary: {self.binary_path}")
            self.project = angr.Project(
                self.binary_path,
                auto_load_libs=False,
                load_options={'auto_load_libs': False}
            )
            logger.info(f"Binary loaded: {self.project.arch.name}")
            return True
        except Exception as e:
            logger.error(f"Failed to load binary: {e}")
            return False

    def build_cfg(self):
        """Build Control Flow Graph"""
        try:
            logger.info("Building Control Flow Graph...")
            self.cfg = self.project.analyses.CFGFast()
            logger.info(f"CFG built with {len(self.cfg.functions)} functions")
            return True
        except Exception as e:
            logger.error(f"Failed to build CFG: {e}")
            return False

    def detect_suspicious_imports(self):
        """Detect suspicious API imports"""
        logger.info("Scanning for suspicious imports...")

        if not hasattr(self.project.loader.main_object, 'imports'):
            logger.warning("No imports found in binary")
            return

        for imp in self.project.loader.main_object.imports:
            imp_name = imp.name if hasattr(imp, 'name') else str(imp)

            # Skip whitelisted functions
            if imp_name in self.whitelist:
                continue

            for technique, keywords in self.signatures.items():
                for keyword in keywords:
                    # More precise matching to avoid false positives
                    if (keyword.lower() == imp_name.lower() or 
                        (len(keyword) > 3 and keyword.lower() in imp_name.lower())):
                        detection = {
                            'type': technique,
                            'import': imp_name,
                            'address': hex(imp.rebased_addr) if hasattr(imp, 'rebased_addr') else 'N/A',
                            'severity': 'HIGH',
                            'timestamp': datetime.now().isoformat()
                        }
                        self.detections[technique].append(detection)
                        logger.warning(f"Detected {technique}: {imp_name}")

    def detect_process_injection(self):
        """Detect process injection patterns"""
        logger.info("Analyzing for process injection patterns...")

        injection_sequence = ['VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread']
        found_sequence = []

        for func_addr in self.cfg.functions:
            func = self.cfg.functions[func_addr]
            func_name = func.name

            if any(keyword in func_name for keyword in injection_sequence):
                found_sequence.append(func_name)

                if len(found_sequence) >= 2:
                    detection = {
                        'type': 'process_injection',
                        'pattern': ' -> '.join(found_sequence),
                        'functions': found_sequence.copy(),
                        'severity': 'CRITICAL',
                        'timestamp': datetime.now().isoformat()
                    }
                    self.detections['process_injection_pattern'].append(detection)
                    logger.critical(f"Process injection pattern detected: {found_sequence}")

    def detect_process_hollowing(self):
        """Detect process hollowing patterns"""
        logger.info("Analyzing for process hollowing patterns...")

        hollowing_indicators = ['NtUnmapViewOfSection', 'SetThreadContext', 'ResumeThread']
        found_indicators = []

        for func_addr in self.cfg.functions:
            func = self.cfg.functions[func_addr]
            func_name = func.name

            if any(keyword in func_name for keyword in hollowing_indicators):
                found_indicators.append(func_name)

                if len(found_indicators) >= 2:
                    detection = {
                        'type': 'process_hollowing',
                        'pattern': ' -> '.join(found_indicators),
                        'functions': found_indicators.copy(),
                        'severity': 'CRITICAL',
                        'timestamp': datetime.now().isoformat()
                    }
                    self.detections['process_hollowing_pattern'].append(detection)
                    logger.critical(f"Process hollowing pattern detected: {found_indicators}")

    def detect_anti_debugging(self):
        """Detect anti-debugging techniques"""
        logger.info("Analyzing for anti-debugging techniques...")

        for func_addr in self.cfg.functions:
            func = self.cfg.functions[func_addr]

            # Check for anti-debug API calls
            for block in func.blocks:
                try:
                    block_bytes = self.project.loader.memory.load(block.addr, block.size)

                    # Check for INT 3 instructions (0xCC)
                    if b'\xcc' in block_bytes:
                        detection = {
                            'type': 'anti_debugging',
                            'technique': 'INT3_breakpoint_check',
                            'address': hex(block.addr),
                            'severity': 'HIGH',
                            'timestamp': datetime.now().isoformat()
                        }
                        self.detections['anti_debugging'].append(detection)
                        logger.warning(f"Anti-debug INT3 at {hex(block.addr)}")

                    # Check for RDTSC (0x0F 0x31) - timing check
                    if b'\x0f\x31' in block_bytes:
                        detection = {
                            'type': 'anti_debugging',
                            'technique': 'RDTSC_timing_check',
                            'address': hex(block.addr),
                            'severity': 'MEDIUM',
                            'timestamp': datetime.now().isoformat()
                        }
                        self.detections['anti_debugging'].append(detection)
                        logger.warning(f"RDTSC timing check at {hex(block.addr)}")

                    # Check for debug register access (DR0-DR7)
                    # MOV from DR registers: 0x0F 0x21
                    if b'\x0f\x21' in block_bytes:
                        detection = {
                            'type': 'anti_debugging',
                            'technique': 'Debug_register_check',
                            'address': hex(block.addr),
                            'severity': 'HIGH',
                            'timestamp': datetime.now().isoformat()
                        }
                        self.detections['anti_debugging'].append(detection)
                        logger.warning(f"Debug register access at {hex(block.addr)}")

                except Exception as e:
                    continue

    def detect_timing_checks(self):
        """Detect timing-based evasion"""
        logger.info("Analyzing for timing-based evasion...")

        timing_apis = ['GetTickCount', 'rdtsc', 'QueryPerformanceCounter', 'clock_gettime']

        for func_addr in self.cfg.functions:
            func = self.cfg.functions[func_addr]
            func_name = func.name

            if any(api in func_name for api in timing_apis):
                detection = {
                    'type': 'timing_evasion',
                    'function': func_name,
                    'address': hex(func_addr),
                    'severity': 'MEDIUM',
                    'timestamp': datetime.now().isoformat()
                }
                self.detections['timing_evasion'].append(detection)
                logger.warning(f"Timing check detected: {func_name}")

    def detect_obfuscation(self):
        """Detect code obfuscation techniques"""
        logger.info("Analyzing for code obfuscation...")

        # Check for high entropy sections
        for section in self.project.loader.main_object.sections:
            if section.is_executable:
                try:
                    data = self.project.loader.memory.load(section.vaddr, min(section.memsize, 1024))
                    entropy = self._calculate_entropy(data)

                    if entropy > 7.0:  # High entropy suggests encryption/packing
                        detection = {
                            'type': 'obfuscation',
                            'technique': 'high_entropy',
                            'section': section.name,
                            'entropy': round(entropy, 2),
                            'severity': 'HIGH',
                            'timestamp': datetime.now().isoformat()
                        }
                        self.detections['obfuscation'].append(detection)
                        logger.warning(f"High entropy section: {section.name} (entropy: {entropy:.2f})")
                except Exception as e:
                    continue

    def _calculate_entropy(self, data):
        """Calculate Shannon entropy"""
        if not data:
            return 0

        entropy = 0
        for x in range(256):
            p_x = float(data.count(bytes([x]))) / len(data)
            if p_x > 0:
                entropy += - p_x * (p_x.bit_length() - 1)
        return entropy

    def symbolic_execution_analysis(self):
        """Perform symbolic execution to detect evasion logic"""
        logger.info("Performing symbolic execution analysis...")

        try:
            # Create initial state
            state = self.project.factory.entry_state()
            simgr = self.project.factory.simulation_manager(state)

            # Explore for a limited time
            simgr.explore(find=lambda s: 'suspicious' in str(s), num_find=5)

            if simgr.found:
                detection = {
                    'type': 'symbolic_analysis',
                    'found_states': len(simgr.found),
                    'severity': 'MEDIUM',
                    'timestamp': datetime.now().isoformat()
                }
                self.detections['symbolic_analysis'].append(detection)
                logger.info(f"Symbolic execution found {len(simgr.found)} interesting states")
        except Exception as e:
            logger.warning(f"Symbolic execution limited: {e}")

    def generate_mitigation_strategy(self):
        """Generate mitigation strategies based on detections"""
        mitigations = {
            'process_injection': [
                'Hook and monitor VirtualAllocEx, WriteProcessMemory, CreateRemoteThread',
                'Enable DEP (Data Execution Prevention)',
                'Use process mitigation policies (SetProcessMitigationPolicy)',
                'Monitor for suspicious cross-process memory operations'
            ],
            'process_hollowing': [
                'Monitor NtUnmapViewOfSection calls',
                'Track process creation and thread context modifications',
                'Enable Process Protection Level',
                'Validate process image integrity'
            ],
            'anti_debugging': [
                'Patch ptrace calls: Replace with NOP (0x90) instructions',
                'Patch INT3 instructions: Replace 0xCC with 0x90',
                'Hook IsDebuggerPresent to return FALSE',
                'Use ScyllaHide or similar anti-anti-debug plugins',
                'Patch RDTSC: Hook and return consistent values',
                'Clear debug register checks: Modify DR register access code'
            ],
            'timing_evasion': [
                'Hook GetTickCount/rdtsc and return consistent values',
                'Use accelerated execution in sandbox',
                'Patch timing comparisons in binary',
                'Set hardware breakpoints on timing functions'
            ],
            'obfuscation': [
                'Use unpacking tools (UPX, UPX-unpack, etc.)',
                'Apply dynamic deobfuscation techniques',
                'Dump decrypted code from memory after execution',
                'Use memory breakpoints to catch self-decryption routines',
                'Try automated unpacking with unipacker or similar tools'
            ],
            'anti_vm': [
                'Patch CPUID checks to hide VM signatures',
                'Modify VM detection strings in memory',
                'Use paravirtualization features to hide VM',
                'Patch registry/file checks for VM artifacts'
            ],
            'anti_sandbox': [
                'Increase timeout values for sandbox analysis',
                'Simulate user interaction (mouse, keyboard)',
                'Hook Sleep functions to skip delays',
                'Modify system artifact checks'
            ]
        }

        active_mitigations = {}
        for technique, detections in self.detections.items():
            if detections:
                base_technique = technique.replace('_pattern', '')
                if base_technique in mitigations:
                    active_mitigations[technique] = mitigations[base_technique]

        return active_mitigations

    def generate_patch_suggestions(self):
        """Generate specific byte-level patch suggestions"""
        patches = []

        for technique, detections in self.detections.items():
            if technique == 'anti_debugging':
                for det in detections:
                    if 'INT3' in det.get('technique', ''):
                        patches.append({
                            'address': det['address'],
                            'original': '0xCC',
                            'patch': '0x90',
                            'description': 'Replace INT3 with NOP',
                            'command': f"echo -ne '\\x90' | dd of=binary bs=1 seek=$((({det['address']}))) conv=notrunc"
                        })
                    elif 'RDTSC' in det.get('technique', ''):
                        patches.append({
                            'address': det['address'],
                            'original': '0x0F 0x31',
                            'patch': '0x90 0x90',
                            'description': 'Replace RDTSC with NOPs',
                            'command': f"echo -ne '\\x90\\x90' | dd of=binary bs=1 seek=$((({det['address']}))) conv=notrunc"
                        })
        
        return patches

    def run_analysis(self):
        """Run complete analysis pipeline"""
        logger.info("=" * 60)
        logger.info("Starting AVSU/AVIZO Evasion Detection Analysis")
        logger.info("=" * 60)

        if not self.load_binary():
            return False

        if not self.build_cfg():
            return False

        # Run all detection modules
        self.detect_suspicious_imports()
        self.detect_process_injection()
        self.detect_process_hollowing()
        self.detect_anti_debugging()
        self.detect_timing_checks()
        self.detect_obfuscation()

        # Optional: symbolic execution (can be slow)
        # self.symbolic_execution_analysis()

        return True

    def get_report(self):
        """Generate analysis report"""
        total_detections = sum(len(v) for v in self.detections.values())

        report = {
            'binary': self.binary_path,
            'analysis_time': datetime.now().isoformat(),
            'total_detections': total_detections,
            'detections': dict(self.detections),
            'severity_summary': self._get_severity_summary(),
            'mitigations': self.generate_mitigation_strategy() if self.enable_mitigation else {}
        }

        return report

    def _get_severity_summary(self):
        """Summarize detections by severity"""
        summary = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}

        for detections in self.detections.values():
            for detection in detections:
                severity = detection.get('severity', 'LOW')
                summary[severity] += 1

        return summary


class MonitoringDashboard:
    """Real-time monitoring dashboard"""

    def __init__(self):
        self.detections = []
        self.running = False
        self.lock = threading.Lock()

    def add_detection(self, detection):
        """Add detection to dashboard"""
        with self.lock:
            self.detections.append(detection)

    def start_monitoring(self, watch_directory):
        """Start monitoring directory for suspicious binaries"""
        self.running = True
        logger.info(f"Starting real-time monitoring on: {watch_directory}")

        watch_path = Path(watch_directory)
        if not watch_path.exists():
            logger.error(f"Watch directory does not exist: {watch_directory}")
            return

        monitored_files = set()

        # First, scan existing files
        logger.info("Scanning for existing binaries...")
        initial_files = self._scan_directory(watch_path)
        logger.info(f"Found {len(initial_files)} potential binaries to analyze")

        for file_path in initial_files:
            if file_path not in monitored_files:
                self._analyze_file(file_path, monitored_files)

        # Then continue monitoring for new files
        logger.info("Continuing real-time monitoring (Press Ctrl+C to stop)...")
        while self.running:
            try:
                current_files = self._scan_directory(watch_path)
                new_files = current_files - monitored_files

                if new_files:
                    logger.info(f"Found {len(new_files)} new file(s)")
                    for file_path in new_files:
                        self._analyze_file(file_path, monitored_files)

                time.sleep(5)  # Check every 5 seconds
            except KeyboardInterrupt:
                logger.info("Monitoring stopped by user")
                break
            except Exception as e:
                logger.error(f"Monitoring error: {e}")

    def _scan_directory(self, watch_path):
        """Scan directory for binary files"""
        binary_extensions = {'.exe', '.dll', '.so', '.dylib', '.bin', '.elf', ''}
        found_files = set()

        try:
            for file_path in watch_path.rglob('*'):
                if file_path.is_file():
                    # Check by extension or if file is executable
                    if (file_path.suffix.lower() in binary_extensions or 
                        self._is_executable(file_path)):
                        found_files.add(file_path)
        except Exception as e:
            logger.error(f"Error scanning directory: {e}")

        return found_files

    def _is_executable(self, file_path):
        """Check if file is executable binary"""
        try:
            # Read first few bytes to check for binary signatures
            with open(file_path, 'rb') as f:
                magic = f.read(4)
                # ELF magic
                if magic[:4] == b'\x7fELF':
                    return True
                # PE magic (MZ)
                if magic[:2] == b'MZ':
                    return True
                # Mach-O magic
                if magic[:4] in [b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf',
                                 b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe']:
                    return True
        except Exception:
            pass
        return False

    def _analyze_file(self, file_path, monitored_files):
        """Analyze a single file"""
        try:
            logger.info(f"Analyzing: {file_path.name}")
            detector = EvasionDetector(str(file_path))
            if detector.run_analysis():
                report = detector.get_report()
                self.add_detection(report)
                self.display_alert(report)
            else:
                logger.warning(f"Failed to analyze: {file_path.name}")
            monitored_files.add(file_path)
        except Exception as e:
            logger.error(f"Error analyzing {file_path.name}: {e}")
            monitored_files.add(file_path)  # Mark as processed to avoid retry

    def display_alert(self, report):
        """Display alert for detected evasion techniques"""
        if report['total_detections'] > 0:
            print("\n" + "=" * 60)
            print(f"⚠️  ALERT: Evasive Techniques Detected in {report['binary']}")
            print("=" * 60)
            print(f"Total Detections: {report['total_detections']}")
            print(f"Severity Summary: {report['severity_summary']}")
            print("\nDetected Techniques:")
            for technique, detections in report['detections'].items():
                if detections:
                    print(f"  - {technique}: {len(detections)} instance(s)")
            print("=" * 60 + "\n")

    def stop_monitoring(self):
        """Stop monitoring"""
        self.running = False

    def generate_dashboard_html(self, output_file='dashboard.html'):
        """Generate HTML dashboard"""
        html = """
<!DOCTYPE html>
<html>
<head>
    <title>Evasion Detection Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #1e1e1e; color: #fff; }
        h1 { color: #4CAF50; }
        .detection { background: #2d2d2d; padding: 15px; margin: 10px 0; border-left: 4px solid #f44336; }
        .critical { border-left-color: #f44336; }
        .high { border-left-color: #ff9800; }
        .medium { border-left-color: #ffeb3b; }
        .low { border-left-color: #4CAF50; }
        .summary { background: #2d2d2d; padding: 20px; margin: 20px 0; border-radius: 5px; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #444; }
        th { background: #333; }
    </style>
</head>
<body>
    <h1>🛡️ AVSU/AVIZO Evasion Detection Dashboard</h1>
    <div class="summary">
        <h2>Detection Summary</h2>
        <p>Total Binaries Analyzed: """ + str(len(self.detections)) + """</p>
        <p>Total Detections: """ + str(sum(d['total_detections'] for d in self.detections)) + """</p>
    </div>
    <h2>Recent Detections</h2>
"""

        for report in self.detections[-10:]:  # Last 10
            html += f"""
    <div class="detection high">
        <h3>{report['binary']}</h3>
        <p><strong>Time:</strong> {report['analysis_time']}</p>
        <p><strong>Total Detections:</strong> {report['total_detections']}</p>
        <p><strong>Severity:</strong> CRITICAL: {report['severity_summary']['CRITICAL']}, 
           HIGH: {report['severity_summary']['HIGH']}, 
           MEDIUM: {report['severity_summary']['MEDIUM']}</p>
    </div>
"""

        html += """
</body>
</html>
"""

        with open(output_file, 'w') as f:
            f.write(html)

        logger.info(f"Dashboard generated: {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description='AVSU/AVIZO Evasion Detection & Mitigation Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze a single binary
  python evasion_detector.py -f malware.exe

  # Analyze with detailed report
  python evasion_detector.py -f malware.exe -o report.json

  # Start real-time monitoring
  python evasion_detector.py -m /path/to/monitor

  # Generate HTML dashboard
  python evasion_detector.py -m /path/to/monitor --dashboard
        """
    )

    parser.add_argument('-f', '--file', help='Binary file to analyze')
    parser.add_argument('-m', '--monitor', help='Directory to monitor for suspicious binaries')
    parser.add_argument('-o', '--output', help='Output report file (JSON)')
    parser.add_argument('--dashboard', action='store_true', help='Generate HTML dashboard')
    parser.add_argument('--no-mitigation', action='store_true', help='Disable mitigation suggestions')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')

    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    if args.file:
        # Single file analysis
        detector = EvasionDetector(args.file, enable_mitigation=not args.no_mitigation)

        if detector.run_analysis():
            report = detector.get_report()

            # Print summary
            print("\n" + "=" * 60)
            print("ANALYSIS REPORT")
            print("=" * 60)
            print(f"Binary: {report['binary']}")
            print(f"Total Detections: {report['total_detections']}")
            print(f"\nSeverity Breakdown:")
            for severity, count in report['severity_summary'].items():
                if count > 0:
                    print(f"  {severity}: {count}")

            print(f"\nDetected Techniques:")
            for technique, detections in report['detections'].items():
                if detections:
                    print(f"  - {technique}: {len(detections)} instance(s)")

            if report['mitigations']:
                print(f"\n📋 Mitigation Strategies:")
                for technique, strategies in report['mitigations'].items():
                    print(f"\n  {technique}:")
                    for strategy in strategies:
                        print(f"    • {strategy}")

            # Save report if requested
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(report, f, indent=2)
                logger.info(f"Report saved to: {args.output}")

    elif args.monitor:
        # Real-time monitoring mode
        dashboard = MonitoringDashboard()

        print("\n" + "=" * 60)
        print("🔍 AVSU/AVIZO Evasion Detection - Monitoring Mode")
        print("=" * 60)
        print(f"Monitoring directory: {args.monitor}")
        print("Press Ctrl+C to stop and generate report\n")

        try:
            dashboard.start_monitoring(args.monitor)
        except KeyboardInterrupt:
            print("\n\n" + "=" * 60)
            print("📊 Monitoring Session Summary")
            print("=" * 60)
            logger.info("Stopping monitoring...")
            dashboard.stop_monitoring()

            # Print summary
            total_analyzed = len(dashboard.detections)
            total_threats = sum(1 for d in dashboard.detections if d['total_detections'] > 0)

            print(f"Total Binaries Analyzed: {total_analyzed}")
            print(f"Binaries with Detections: {total_threats}")

            if total_threats > 0:
                print("\n⚠️  Detected Evasion Techniques:")
                technique_counts = defaultdict(int)
                for report in dashboard.detections:
                    for technique, detections in report['detections'].items():
                        if detections:
                            technique_counts[technique] += len(detections)

                for technique, count in sorted(technique_counts.items(), key=lambda x: x[1], reverse=True):
                    print(f"  • {technique}: {count} instance(s)")

            print("=" * 60)
        finally:
            if args.dashboard:
                dashboard.generate_dashboard_html()
                print(f"\n📄 HTML Dashboard generated: dashboard.html")

    else:
        parser.print_help()
        sys.exit(1)


if __name__ == '__main__':
    main()
