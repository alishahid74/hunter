# SymbolicHunter 🔍

A comprehensive symbolic execution framework powered by angr for automated vulnerability discovery, exploit generation, and binary analysis with a modern web interface.


## 🌟 Overview

SymbolicHunter is an advanced binary analysis tool that combines symbolic execution, taint analysis, and automated exploit generation to identify vulnerabilities in compiled binaries. It features both a powerful command-line interface and a modern web dashboard for interactive analysis.

### 🎯 Key Features

#### Core Analysis Engine
- Full Symbolic Execution - Powered by angr for deep program analysis
- Control Flow Graph (CFG) Analysis - Automatic function and basic block discovery
- Advanced Taint Analysis - Track user input from sources to dangerous sinks
- Multi-Category Vulnerability Detection - Buffer overflows, format strings, NULL derefs, command injection, and more
- Code Coverage Tracking - Real-time measurement of analysis completeness
- Anti-Analysis Detection - Identify debugger/VM evasion techniques
- Smart Path Prioritization - Focus on dangerous API calls and high-risk paths

#### Advanced Features
- 🌐 Web Dashboard - Modern Flask-based interface with real-time updates
- 📊 HTML Report Generation - Beautiful, interactive reports with visualizations
- 🧪 Automatic Exploit Testing - Verify vulnerabilities with automated testing
- 🔍 Signature Generation - Auto-generate YARA, Snort, and SIGMA detection rules
- 💾 Memory Analysis - Detect shellcode, ROP gadgets, heap sprays, and injected code
- 📝 PoC Script Generation - Create ready-to-run Python exploit scripts
- 🚨 IOC Extraction - Generate indicators of compromise for threat intelligence

---

## 📦 Installation

### Prerequisites
- Python 3.8 or higher
- Linux, macOS, or Windows with WSL
- 4GB+ RAM recommended for complex binaries

### Quick Install

```bash
# Clone the repository
git clone https://github.com/alishahid74/SymbolicHunter.git
cd SymbolicHunter

# Install dependencies
pip install -r requirements.txt

# Run setup script
chmod +x setup.sh
./setup.sh
```

### Manual Installation

```bash
# Install core dependencies
pip install angr claripy

# Install web dashboard dependencies
pip install Flask Flask-SocketIO python-socketio werkzeug

# Verify installation
python3 -c "import angr; print('✓ angr installed successfully')"
python3 -c "import flask; print('✓ Flask installed successfully')"
```

---

## 🏗️ Project Structure

```
SymbolicHunter/
├── symbolic_hunter.py          # Core symbolic execution engine
├── symbolic_hunter_complete.py # Integrated tool with all features
├── web_dashboard.py            # Flask web interface
├── config.py                   # Configuration settings
├── requirements.txt            # Python dependencies
├── setup.sh                    # Setup script
├── start_dashboard.sh          # Web dashboard launcher
├── README.md                   # This file
│
├── modules/                    # Analysis modules
│   ├── __init__.py            # Module initialization
│   ├── reporting.py           # HTML/PDF report generation
│   ├── exploit_tester.py      # Automatic exploit testing
│   ├── signature_gen.py       # YARA/Snort/SIGMA generation
│   ├── memory_analyzer.py     # Memory dump analysis
│   └── utils.py               # Shared utility functions
│
├── templates/                  # Web UI templates
│   ├── dashboard.html         # Main dashboard interface
│   └── report_template.html   # Analysis report template
│
├── uploads/                    # Uploaded binaries (auto-created)
├── output/                     # Analysis results (auto-created)
└── signatures/                 # Generated signatures (auto-created)
```

---

## 🚀 Quick Start

### Option 1: Web Dashboard (Recommended for Beginners)

The easiest way to use SymbolicHunter is through the web interface:

```bash
# Start the web dashboard
./start_dashboard.sh

# Or manually:
python3 web_dashboard.py

# Open your browser to: http://localhost:5000
```

Web Dashboard Features.
- 🖱️ Drag-and-drop binary upload
- ⚙️ Interactive configuration (timeout, max-states, analysis options)
- 📊 Real-time analysis progress with live log streaming
- 📈 Beautiful visualizations and statistics
- 📄 Downloadable reports (HTML, JSON, signatures)
- 📜 Analysis history and job management
- 🔍 WebSocket-based real-time updates

### Option 2: Command Line Interface

For advanced users and automation:

#### Basic Analysis

```bash
# Analyze a binary
python3 symbolic_hunter.py malware.exe

# Enable verbose output
python3 symbolic_hunter.py binary.exe -v

# Export results to JSON
python3 symbolic_hunter.py binary.exe -o results.json

# Generate PoC exploit script
python3 symbolic_hunter.py binary.exe --poc exploits.py
```

#### Complete Analysis (All Features)

```bash
# Run comprehensive analysis with all modules
python3 symbolic_hunter_complete.py binary.exe --all -v --output-dir results/

# This single command will:
# ✅ Perform symbolic execution
# ✅ Generate interactive HTML report
# ✅ Test exploits automatically
# ✅ Create detection signatures (YARA, Snort, SIGMA)
# ✅ Analyze memory patterns
# ✅ Export all results in multiple formats
```

#### Target-Specific Analysis

```bash
# Find path to specific function
python3 symbolic_hunter.py app.exe --find-function "authenticate" -v

# Deep analysis with extended exploration
python3 symbolic_hunter.py target.exe -v --max-states 5000 --timeout 1800

# Quick 30-second triage scan
python3 symbolic_hunter.py binary.exe --timeout 30 --max-states 200
```

---

## 💻 Web Dashboard Guide

### Starting the Dashboard

```bash
# Method 1: Using the start script (recommended)
./start_dashboard.sh

# Method 2: Direct execution
python3 web_dashboard.py

# Method 3: Custom port
FLASK_PORT=8080 python3 web_dashboard.py
```

The dashboard will be available at http://localhost:5000 (or your custom port).

### Using the Web Interface

1. Upload Binary
   - Click "Upload" or drag-and-drop your binary file
   - Supports PE (.exe, .dll) and ELF files
   - Maximum file size: 100MB

2. Configure Analysis
   - Set max states to explore (default: 1000)
   - Set timeout in seconds (default: 300)
   - Enable features:
     - ☑️ Verbose output
     - ☑️ Generate HTML report
     - ☑️ Test exploits
     - ☑️ Generate signatures
     - ☑️ Memory analysis
     - ☑️ All features (enable everything)

3. Start Analysis
   - Click "Start Analysis"
   - Watch real-time progress updates
   - View live log output via WebSocket

4. View Results
   - Interactive HTML report
   - Download JSON results
   - Access generated signatures
   - View exploit candidates
   - Download PoC scripts

### API Endpoints

The web dashboard exposes a RESTful API for automation:

```python
import requests
import json

# Upload binary
files = {'file': open('malware.exe', 'rb')}
upload_response = requests.post('http://localhost:5000/api/upload', files=files)
filepath = upload_response.json()['filepath']

# Start analysis
config = {
    'binary_path': filepath,
    'options': {
        'verbose': True,
        'max_states': 1000,
        'timeout': 300,
        'all_features': True
    }
}
analysis_response = requests.post(
    'http://localhost:5000/api/analyze',
    json=config
)
job_id = analysis_response.json()['job_id']

# Check status
status = requests.get(f'http://localhost:5000/api/job/{job_id}')
print(status.json())

# Get results (when complete)
results = requests.get(f'http://localhost:5000/api/job/{job_id}/results')
print(results.json())

# Download HTML report
report = requests.get(f'http://localhost:5000/api/job/{job_id}/report')
with open('report.html', 'wb') as f:
    f.write(report.content)
```

## 🔧 Command Line Reference

### symbolic_hunter.py (Core Engine)

```
usage: symbolic_hunter.py [-h] [-v] [--max-states N] [--timeout SECS]
                          [-o FILE] [--poc FILE] [--find-function NAME]
                          binary

Required Arguments:
  binary                Path to binary file to analyze

Analysis Options:
  -v, --verbose         Enable detailed output and debug information
  --max-states N        Maximum states to explore (default: 1000)
  --timeout SECS        Analysis timeout in seconds (default: 300)
  --find-function NAME  Search for paths to specific function by name

Output Options:
  -o FILE              Export results to JSON file
  --poc FILE           Generate PoC exploit Python script

Examples:
  # Basic analysis
  python3 symbolic_hunter.py malware.exe

  # Verbose with JSON export
  python3 symbolic_hunter.py binary.exe -v -o report.json

  # Find path to specific function
  python3 symbolic_hunter.py app.exe --find-function "authenticate"

  # Deep analysis
  python3 symbolic_hunter.py target.exe --max-states 5000 --timeout 1800
```

### symbolic_hunter_complete.py (Full Suite)

```
usage: symbolic_hunter_complete.py [-h] [-v] [--max-states N] [--timeout SECS]
                                   [-o FILE] [--output-dir DIR]
                                   [--html-report FILE] [--test-exploits]
                                   [--generate-signatures] [--memory-analysis]
                                   [--poc FILE] [--all] [--find-function NAME]
                                   binary

Required Arguments:
  binary                Path to binary file to analyze

Analysis Options:
  -v, --verbose         Enable detailed output
  --max-states N        Maximum states to explore (default: 1000)
  --timeout SECS        Analysis timeout in seconds (default: 300)
  --find-function NAME  Search for paths to specific function

Output Options:
  -o FILE               Export JSON results
  --output-dir DIR      Output directory for all generated files
  --html-report FILE    Generate interactive HTML report
  --poc FILE            Generate PoC exploit script

Feature Modules:
  --test-exploits       Automatically test generated exploits
  --generate-signatures Generate YARA/Snort/SIGMA detection rules
  --memory-analysis     Perform memory pattern analysis
  --all                 Enable ALL analysis features

Examples:
  # Full analysis with all features
  python3 symbolic_hunter_complete.py binary.exe --all -v

  # Generate HTML report only
  python3 symbolic_hunter_complete.py binary.exe --html-report report.html

  # Test exploits automatically
  python3 symbolic_hunter_complete.py binary.exe --test-exploits

  # Generate detection signatures
  python3 symbolic_hunter_complete.py binary.exe --generate-signatures

  # Everything with custom output directory
  python3 symbolic_hunter_complete.py binary.exe --all --output-dir results/
```

---

## 💡 Usage Examples

### 1. Security Research & Vulnerability Discovery

```bash
# Comprehensive vulnerability analysis
python3 symbolic_hunter_complete.py target.exe --all -v \
    --max-states 5000 \
    --timeout 1800 \
    --output-dir vulnerability_report/

# Output includes:
# - Detailed vulnerability report (HTML)
# - Exploit candidates with PoC code
# - Detection signatures (YARA/Snort/SIGMA)
# - Memory analysis findings
# - Complete JSON results
```

### 2. CTF Challenge Solving

```bash
# Find path to win() function and generate exploit
python3 symbolic_hunter.py challenge.bin \
    --find-function "win" \
    -v \
    --poc solution.py

# The tool will:
# ✓ Find execution path to win()
# ✓ Generate input that reaches win()
# ✓ Create runnable PoC script
```

### 3. Malware Analysis

```bash
# Full malware analysis with all features
python3 symbolic_hunter_complete.py suspicious.exe \
    --all \
    -v \
    --output-dir malware_analysis/

# Generates:
# - Behavioral analysis report
# - Anti-analysis technique detection
# - IOC extraction
# - YARA signatures for detection
# - Dangerous API call analysis
```

### 4. Penetration Testing

```bash
# Automated vulnerability assessment
python3 symbolic_hunter_complete.py webapp.exe \
    --html-report pentest_report.html \
    --test-exploits \
    --generate-signatures \
    -v

# Creates professional pentest deliverables:
# - Executive summary HTML report
# - Confirmed vulnerabilities (tested exploits)
# - Detection signatures for remediation verification
```

### 5. Binary Triage (Quick Scan)

```bash
# 60-second quick security scan
python3 symbolic_hunter.py unknown.exe \
    --timeout 60 \
    --max-states 200 \
    -o quick_scan.json

# Fast initial assessment:
# - High-level vulnerability indicators
# - Dangerous API calls
# - Basic taint analysis
# - JSON export for further processing
```

---

## 📊 Understanding the Output

### Terminal Output

```
╔═══════════════════════════════════════════════════════════╗
║           SymbolicHunter - angr Analysis Tool             ║
╚═══════════════════════════════════════════════════════════╝

[*] Loading binary: malware.exe
[+] Binary loaded successfully
    Architecture: X86
    Entry point: 0x401400
    Base address: 0x400000

[+] CFG analysis complete
    Functions discovered: 535
    Basic blocks: 2433
    Edges: 3127

[!] Found 21 dangerous API calls
    [MEMORY] 5 calls - VirtualProtect, VirtualAlloc
    [PROCESS] 1 calls - CreateProcess
    [LIBRARY] 2 calls - LoadLibrary, GetProcAddress
    [ANTI_DEBUG] 3 calls - IsDebuggerPresent

[!!!] Anti-Analysis Techniques Detected!
      This binary may evade debugging/analysis
      - anti_debug: IsDebuggerPresent at 0x401500

[*] Starting symbolic execution with angr...
    Max states: 1000
    Timeout: 300s

[*] Step 50: Active=12, Dead=38, Error=0, Exploits=3, Time=25.3s
[*] Step 100: Active=8, Dead=92, Error=0, Exploits=5, Time=58.7s

[!!!] TAINT ANALYSIS - Critical Findings:
    Found 5 tainted data flows to dangerous sinks!

    [COMMAND INJECTION] (2 instances)
      1. system() at 0x401234
         Tainted args: arg0
         Source: stdin
         → Input reaches system() - CRITICAL

    [BUFFER OVERFLOW] (3 instances)
      1. strcpy() at 0x405678
         Tainted destination pointer
         Source: argv[1]
         → Unbounded copy - HIGH RISK

╔════════════════════════════════════════════════════════╗
║                  ANALYSIS COMPLETE                     ║
╚════════════════════════════════════════════════════════╝

[*] Execution Statistics:
    Paths explored: 150
    States analyzed: 750
    Code coverage: 23.5%
    Time elapsed: 245.01s

[*] Vulnerability Summary:
    Total issues found: 157
    Unique vulnerabilities: 5
    Buffer Overflows: 3
    Command Injections: 2
    NULL Dereferences: 0

[*] Exploit Generation:
    Candidates generated: 5
    High confidence: 3
    Medium confidence: 2

╔════════════════════════════════════════════════════════╗
║              SYMBOLIC HUNTER SUMMARY                   ║
╚════════════════════════════════════════════════════════╝

Binary: malware.exe
Risk Level: CRITICAL ⚠️
Analysis Time: 245.01s

Key Findings:
  ⚠️  157 potential security issues (5 unique)
  💉 5 tainted data flows to dangerous sinks
  🎯 5 exploit candidates generated
  ⚡ 21 dangerous API calls detected
  🛡️ 3 anti-analysis techniques found
  ✓ Code coverage: 23.5%

Top Recommendations:
  • IMMEDIATE manual review required
  • Deploy in isolated sandbox environment
  • Verify all 5 taint sinks manually
  • Test exploit inputs in controlled setting
  • Review dangerous API usage patterns

[+] Results exported to: results.json
[+] PoC script generated: exploits.py
[+] HTML report: report.html
```

### HTML Report Features

The generated HTML reports (`--html-report`) include:

#### 1. Executive Summary Dashboard
- Risk Level Badge - Color-coded risk assessment (LOW/MEDIUM/HIGH/CRITICAL)
- Key Metrics Cards - Total vulnerabilities, taint sinks, code coverage, analysis time
- Animated Statistics - Count-up animations and progress bars
- Quick Stats Grid - Functions discovered, paths explored, exploit candidates

#### 2. Risk Assessment Section
- Overall risk level with visual indicator
- Risk factors breakdown
- Severity distribution chart
- Timeline of discovery

#### 3. Taint Analysis Visualization
- Data Flow Graphs - Visual representation of taint propagation
- Source-to-Sink Paths - Complete flow from input to dangerous function
- Vulnerability Type Grouping - Organized by command injection, buffer overflow, etc.
- Exploit Payloads - Hex dumps of generated inputs

#### 4. Vulnerability Browser
- Filterable List - Sort by type, severity, or address
- Detailed Cards - Each vulnerability with full context
- Code Snippets - Relevant code sections
- Remediation Advice - Specific fix recommendations

#### 5. Dangerous API Calls
- Categorized Display - Grouped by MEMORY, PROCESS, NETWORK, etc.
- Risk Indicators - Color-coded by category
- Usage Context - Where and how APIs are called
- Count Statistics - Frequency analysis

#### 6. Code Coverage Visualization
- Progress Bar - Visual coverage percentage
- Hit Addresses - List of explored locations
- Coverage Heatmap - Areas of high/low coverage
- Basic Block Statistics - Total vs. explored blocks

#### 7. Recommendations
- Prioritized action items
- Security best practices
- Specific remediations for found vulnerabilities
- Next steps for analysis

#### Snort Rule Example

```
# Auto-generated Snort rule by SymbolicHunter
# Date: 2025-10-12
# Binary: malware.exe

alert tcp any any -> any any (
    msg:"SymbolicHunter - Potential malware.exe exploit detected";
    flow:established,to_server;
    content:"|2f 62 69 6e 2f 73 68|";       // /bin/sh
    content:"|41 41 41 41|";                 // AAAA pattern
    reference:url,github.com/yourusername/SymbolicHunter;
    classtype:attempted-admin;
    sid:9000001;
    rev:1;
)
```


## 📚 Module Documentation

### modules/reporting.py

Generates beautiful HTML reports with interactive visualizations.

```python
from modules.reporting import generate_report, ReportGenerator

# Quick report generation
generate_report(analysis_results, 'report.html')

# Advanced usage
generator = ReportGenerator(analysis_results)
html_path = generator.generate_html_report('custom_report.html')
print(f"Report saved to: {html_path}")
```

Features.
- Modern gradient design with responsive layout
- Interactive statistics cards with animations
- Taint flow visualization
- Vulnerability browser with filtering
- Code coverage charts
- Print-friendly CSS


Features.
- Automatic crash detection (SIGSEGV, SIGABRT, etc.)
- Timeout handling for hung processes
- Sandbox execution (recommended)
- Detailed test reports with exit codes
- Crash analysis and signal identification

### modules/signature_gen.py

Generated Signatures:*
- YARA - Malware detection rules with API strings and patterns
- Snort/Suricata - Network IDS rules for exploit detection
- SIGMA - SIEM rules for process/event detection
- IOC Lists - File hashes, API calls, behaviors

Detection Capabilities.
- Shellcode Patterns - NOP sleds, x86 instruction sequences, common shellcode signatures
- ROP Gadgets - pop/ret sequences, useful gadget identification
- Heap Spray - Repeated patterns indicating heap spray attacks
- Suspicious Strings - URLs, registry keys, shell commands, file paths
- Injected Code - PE headers, DLL injection signatures
- Executable Code Detection - Heuristic-based code identification



Utility Functions.
- calculate_hashes() - MD5, SHA1, SHA256
- format_bytes() - Human-readable file sizes
- get_file_info() - Comprehensive file metadata
- extract_strings() - ASCII/Unicode string extraction
- assess_risk_level() - Risk calculation algorithm
- generate_summary_stats() - Analysis statistics
- create_progress_bar() - ASCII progress visualization
- print_*() - Colored terminal output
- is_pe_file()`, `is_elf_file() - Binary type detection


## 🎓 Advanced Usage

### Custom Analysis Pipeline

Create sophisticated workflows by combining modules:

```python
#!/usr/bin/env python3
"""
Custom SymbolicHunter Analysis Pipeline
"""
from symbolic_hunter import SymbolicHunter
from modules import *
import json

def comprehensive_analysis(binary_path, output_dir='results/'):
    """Run complete analysis workflow"""
    
    print_banner()
    print_section("Starting Comprehensive Analysis")
    
    # 1. Get file information
    file_info = get_file_info(binary_path)
    print_info(f"Analyzing: {file_info['name']}")
    print_info(f"Type: {file_info['type']}")
    print_info(f"Size: {file_info['size_formatted']}")
    print_info(f"SHA256: {file_info['hashes']['sha256']}")
    
    # 2. Run symbolic execution
    print_section("Symbolic Execution Analysis")
    hunter = SymbolicHunter(
        binary_path,
        verbose=True,
        max_states=2000,
        timeout=600
    )
    
    hunter.print_header()
    hunter.explore_binary()
    
    # 3. Collect results
    results = {
        'binary': binary_path,
        'file_info': file_info,
        'statistics': hunter.stats,
        'vulnerabilities': dict(hunter.vulnerabilities),
        'taint_analysis': {
            'tainted_sinks': hunter.taint_sinks,
            'data_flows': hunter.data_flows,
            'taint_sources': list(hunter.taint_sources)
        },
        'dangerous_functions': hunter.dangerous_functions,
        'exploit_candidates': hunter.exploit_candidates,
        'anti_analysis': hunter.anti_analysis_detected
    }
    
    # 4. Generate HTML report
    print_section("Generating HTML Report")
    report_path = f"{output_dir}/report.html"
    generate_report(results, report_path)
    print_success(f"HTML report: {report_path}")
    
    # 5. Test exploits
    if hunter.exploit_candidates:
        print_section("Testing Exploit Candidates")
        test_results = test_exploits(
            binary_path,
            hunter.exploit_candidates,
            timeout=10
        )
        results['exploit_tests'] = test_results
        print_success(f"Confirmed {test_results['crashed']} vulnerabilities")
    
    # 6. Generate signatures
    print_section("Generating Detection Signatures")
    sig_files = generate_signatures(
        binary_path,
        results,
        f"{output_dir}/signatures/"
    )
    results['signatures'] = sig_files
    for sig_type, path in sig_files.items():
        print_success(f"{sig_type.upper()}: {path}")
    
    # 7. Memory analysis
    print_section("Memory Pattern Analysis")
    mem_findings = analyze_memory(binary_path=binary_path)
    results['memory_analysis'] = mem_findings
    
    print_info(f"Shellcode patterns: {len(mem_findings['shellcode'])}")
    print_info(f"ROP gadgets: {len(mem_findings['rop_gadgets'])}")
    print_info(f"Suspicious strings: {len(mem_findings['suspicious_strings'])}")
    
    # 8. Risk assessment
    print_section("Risk Assessment")
    risk_level, risk_color = assess_risk_level(results)
    print(f"Overall Risk: {risk_color}{risk_level}{Colors.END}")
    
    # 9. Save complete results
    analysis_json = f"{output_dir}/complete_analysis.json"
    save_json(results, analysis_json)
    print_success(f"Complete results: {analysis_json}")
    
    # 10. Generate summary
    print_section("Analysis Summary")
    stats = generate_summary_stats(results)
    
    print(f"Total Vulnerabilities: {stats['total_vulnerabilities']}")
    print(f"Taint Sinks: {stats['taint_sinks']}")
    print(f"Exploit Candidates: {stats['exploit_candidates']}")
    print(f"Dangerous APIs: {stats['dangerous_apis']}")
    print(f"Code Coverage: {stats['code_coverage']:.1f}%")
    print(f"Analysis Time: {stats['analysis_time']:.2f}s")
    
    print_section("Analysis Complete", Colors.GREEN)
    print_success(f"All results saved to: {output_dir}")
    
    return results

if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print("Usage: python custom_pipeline.py <binary>")
        sys.exit(1)
    
    comprehensive_analysis(sys.argv[1])
```

## 🔬 Technical Details

### Symbolic Execution Algorithm

SymbolicHunter uses angr's symbolic execution engine with the following approach:

1. State Initialization
   ```python
   # Create initial state with symbolic stdin
   state = project.factory.entry_state()
   stdin_data = claripy.BVS('stdin', 8 * 200)  # 200 bytes symbolic
   stdin_file = angr.storage.SimFile('stdin', content=stdin_data)
   state.posix.stdin = stdin_file
   ```

2. Simulation Manager
   ```python
   simgr = project.factory.simulation_manager(state)
   simgr.use_technique(DFS())  # Depth-first search
   ```

3. Path Exploration
   - Explores multiple execution paths simultaneously
   - Tracks symbolic constraints on inputs
   - Uses Z3 SMT solver to determine path feasibility
   - Generates concrete inputs for each viable path

4. State Analysis
   - Check for vulnerability patterns at each state
   - Track taint propagation through registers/memory
   - Identify dangerous function calls
   - Generate exploit inputs when vulnerabilities found

### Taint Analysis Implementation

Algorithm.

1. Mark Taint Sources
   ```python
   taint_sources = ['stdin', 'argv', 'file_input']
   for var in state.solver.get_variables():
       if any(src in str(var) for src in taint_sources):
           # Mark as tainted
   ```

2. Track Propagation
   - Monitor data flow through registers (RAX, RBX, RCX, etc.)
   - Track memory operations (load/store)
   - Follow function call arguments

3. Detect Dangerous Sinks
   ```python
   dangerous_sinks = {
       'system': 'Command Injection',
       'strcpy': 'Buffer Overflow',
       'printf': 'Format String',
       # ...
   }
   ```

4. Verify Taint Path
   ```python
   if arg.symbolic:
       arg_vars = state.solver.get_variables(arg)
       for var_name in arg_vars:
           if 'stdin' in str(var_name):
               # Tainted data reaches sink!
   ```

5. Generate Exploit Input
   ```python
   if state.solver.satisfiable():
       exploit_input = state.solver.eval(stdin_var, cast_to=bytes)
   ```


### Code Coverage Calculation

```python
coverage_percentage = (unique_addresses_hit / total_basic_blocks) * 100
```

Coverage Factors.
- Higher max_states → Better coverage
- Longer timeout → More paths explored
- Path prioritization → Focus on critical code

Typical Coverage.
- Simple binaries: 50-80%
- Complex applications: 10-30%
- Obfuscated/packed: 5-15%

### Risk Assessment Algorithm

```python
def calculate_risk(results):
    score = 0
    
    # Vulnerability scoring
    score += len(results['buffer_overflows']) * 10
    score += len(results['command_injections']) * 15
    score += len(results['format_strings']) * 10
    score += len(results['null_derefs']) * 5
    
    # Taint analysis bonus (CRITICAL indicator)
    score += len(results['taint_sinks']) * 25
    
    # Anti-analysis penalty
    score += len(results['anti_analysis']) * 20
    
    # Unconstrained execution (worst case)
    if results.get('unconstrained'):
        score += 50
    
    # Determine level
    if score >= 100:
        return 'CRITICAL'
    elif score >= 50:
        return 'HIGH'
    elif score >= 20:
        return 'MEDIUM'
    else:
        return 'LOW'
```

---

## ⚡ Performance Optimization

### Tuning Parameters

#### Quick Triage (30-60 seconds)
```bash
python3 symbolic_hunter.py binary.exe \
    --timeout 60 \
    --max-states 200
```
Best for. Initial assessment, batch processing

#### Balanced Analysis (5-10 minutes)
```bash
python3 symbolic_hunter.py binary.exe \
    --timeout 600 \
    --max-states 1000
```
Best for. Standard analysis, most binaries

#### Deep Analysis (30+ minutes)
```bash
python3 symbolic_hunter.py binary.exe \
    --timeout 1800 \
    --max-states 5000
```
Best for. Critical binaries, research, CVE discovery

### Optimization Tips

1. Target Specific Functions
   ```bash
   # Faster than full exploration
   python3 symbolic_hunter.py app.exe --find-function "process_input"
   ```

2. Adjust State Limits Based on Binary Size
   - Small binaries (<100KB): max-states 2000-5000
   - Medium binaries (100KB-1MB): max-states 1000-2000
   - Large binaries (>1MB): max-states 500-1000

3. Use Appropriate Timeouts
   - Simple binaries: 60-300 seconds
   - Complex binaries: 300-900 seconds
   - Obfuscated/packed: 900-1800 seconds

4. Monitor Memory Usage
   ```bash
   # Check memory during analysis
   /usr/bin/time -v python3 symbolic_hunter.py binary.exe
   ```

5. Enable State Pruning (Automatic in code)
   - Keeps only top 50 active states when >100 active
   - Prevents memory exhaustion
   - Focuses on most promising paths

### Performance Benchmarks

| Binary Size | States | Timeout | Avg Time | Avg Coverage |
|-------------|--------|---------|----------|--------------|
| 50KB        | 1000   | 300s    | 45s      | 65%          |
| 500KB       | 1000   | 300s    | 180s     | 35%          |
| 2MB         | 1000   | 300s    | 290s     | 18%          |
| 10MB        | 500    | 600s    | 580s     | 8%           |

Benchmarks on Intel i7-9700K, 16GB RAM

## Troubleshooting

### Common Issues

#### Issue: angr Import Errors
```
ImportError: No module named 'angr'
ModuleNotFoundError: No module named 'claripy'
```

Solution.
```bash
# Upgrade pip first
pip install --upgrade pip

# Install angr and dependencies
pip install angr claripy

# If still failing, use virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install angr claripy Flask Flask-SocketIO
```

#### Issue: Flask/SocketIO Errors
```
ImportError: cannot import name 'SocketIO' from 'flask_socketio'
```

Solution.
```bash
pip install Flask Flask-SocketIO python-socketio werkzeug
# Or use requirements.txt
pip install -r requirements.txt
```

#### Issue: Analysis Timeout
```
[!] Analysis timed out after 300 seconds
```

Solutions.
```bash
# 1. Increase timeout
python3 symbolic_hunter.py binary.exe --timeout 900

# 2. Reduce max states
python3 symbolic_hunter.py binary.exe --max-states 500

# 3. Target specific function
python3 symbolic_hunter.py binary.exe --find-function "main"

# 4. Use quick triage mode
python3 symbolic_hunter.py binary.exe --timeout 60 --max-states 200
```

#### Issue: No Vulnerabilities Found
```
[*] Vulnerability Summary: Total issues found: 0
```

Solutions.
1. Increase exploration depth.
   ```bash
   python3 symbolic_hunter.py binary.exe --max-states 5000 --timeout 1800
   ```

2. Binary may be secure or angr cannot analyze it effectively
   - Try with `--verbose` for more details
   - Check if binary is packed/obfuscated

3. Target specific vulnerable functions.
   ```bash
   python3 symbolic_hunter.py binary.exe --find-function "vulnerable_func"
   ```

#### Issue: Module Import Errors
```
ModuleNotFoundError: No module named 'modules.reporting'
```

Solution
```bash
# Ensure proper directory structure
./setup.sh

# Or manually
mkdir -p modules templates output signatures
touch modules/__init__.py

# Verify __init__.py contains imports
cat modules/__init__.py
```

#### Issue: Web Dashboard Not Starting
```
Address already in use: 0.0.0.0:5000
```

Solution.
```bash
# Option 1: Use different port
python3 web_dashboard.py --port 8080

# Option 2: Kill process using port 5000
lsof -ti:5000 | xargs kill -9

# Option 3: Change port in code
# Edit web_dashboard.py, line: socketio.run(app, port=5000)
```

#### Issue: File Upload Fails (Web Dashboard)
```
413 Request Entity Too Large
```

Solution.
Edit `web_dashboard.py`:
```python
# Increase max file size (currently 100MB)
app.config['MAX_CONTENT_LENGTH'] = 200 * 1024 * 1024  # 200MB
```

#### Issue: Permission Denied
```
PermissionError: [Errno 13] Permission denied: 'output/'
```

Solution.
```bash
# On Linux/Mac
chmod +x setup.sh symbolic_hunter.py start_dashboard.sh
chmod -R 755 output/ signatures/ uploads/

# Create directories if missing
mkdir -p output signatures uploads templates
chmod 755 output signatures uploads templates
```

#### Issue: Constraint Solver Timeout
```
[!] Z3 solver timeout
claripy.errors.ClaripyZ3Error: timeout
```

Solution.
```bash
# Reduce complexity
python3 symbolic_hunter.py binary.exe --max-states 300 --timeout 120

# Or target specific areas
python3 symbolic_hunter.py binary.exe --find-function "target_func"
```

#### Issue: Binary Format Not Supported
```
[!] Error: Unsupported binary format
```

Solution.
- Ensure binary is PE (Windows) or ELF (Linux
- Check if packed/obfuscated. Try unpacking with UPX or similar
- Verify file type
  ```bash
  file binary.exe
  ```

#### Issue: Out of Memory
```
MemoryError: Unable to allocate memory
killed
```

Solution
```bash
# 1. Reduce state limit drastically
python3 symbolic_hunter.py binary.exe --max-states 200

# 2. Close other applications
# 3. Use system with more RAM (8GB+ recommended)

# 4. Monitor memory usage
python3 -c "
import resource
resource.setrlimit(resource.RLIMIT_AS, (4*1024*1024*1024, -1))  # 4GB limit
" && python3 symbolic_hunter.py binary.exe
```

### Debug Mode

Enable maximum verbosity for troubleshooting:

```bash
# Full debug output
python3 symbolic_hunter.py binary.exe -v --max-states 100 --timeout 60 2>&1 | tee debug.log

# Python debug mode
python3 -v symbolic_hunter.py binary.exe

# Check angr logging
python3 -c "
import logging
logging.getLogger('angr').setLevel(logging.DEBUG)
from symbolic_hunter import SymbolicHunter
hunter = SymbolicHunter('binary.exe', verbose=True)
hunter.explore_binary()
"
```

### Getting Help

ignore for now this part.
If issues persist:

1. Check GitHub Issues. https://github.com/alishahid74/SymbolicHunter.git
2. Create New Issue with:
   - Error message (full traceback)
   - Binary type (PE/ELF, 32/64-bit)
   - Command used
   - Python version: `python3 --version`
   - angr version: `pip show angr`
   - Operating system

## 🎯 Use Cases

### 🔐 Security Research & 0-Day Discovery

Objective. Find unknown vulnerabilities in software

```bash
# Deep vulnerability research
python3 symbolic_hunter_complete.py proprietary_software.exe \
    --all -v \
    --max-states 10000 \
    --timeout 3600 \
    --output-dir 0day_research/

# Focus on specific attack surface
python3 symbolic_hunter.py network_service.exe \
    --find-function "handle_request" \
    --max-states 5000 \
    -v
```


### 🎮 CTF Competition Solving

Objective. Solve reverse engineering and pwn challenges

```bash
# Find path to win/flag function
python3 symbolic_hunter.py ctf_challenge \
    --find-function "win" \
    --poc solution.py \
    -v

# Alternative: Find any path that prints flag
python3 symbolic_hunter.py challenge.bin \
    --max-states 2000 \
    --timeout 300 \
    -v

# Run generated solution
python3 solution.py | nc ctf.server.com 1337
```

Success Stories.
- Automatically solve buffer overflow challenges
- Find correct input for authentication bypass
- Discover hidden code paths to flags

### 🛡️ Penetration Testing

Objective. Comprehensive security assessment

```bash
# Full penetration test analysis
python3 symbolic_hunter_complete.py client_application.exe \
    --all \
    --html-report pentest_findings.html \
    --test-exploits \
    --generate-signatures \
    --output-dir pentest_deliverables/
```

Pentest Deliverables.
- Executive summary (HTML report)
- Technical findings with CVSS scores
- Verified exploits (tested)
- Remediation recommendations
- Detection signatures for validation

### 🔬 Malware Analysis

Objective. Understand malicious behavior and create detection rules

```bash
# Comprehensive malware analysis
python3 symbolic_hunter_complete.py malware_sample.exe \
    --all -v \
    --memory-analysis \
    --generate-signatures \
    --output-dir malware_report/
```

Analysis Output.
- Behavioral analysis (API calls, anti-analysis)
- IOCs (hashes, network indicators, file paths)
- YARA signatures for detection
- Threat intelligence feeds
- Sandboxing recommendations

### 🏢 Enterprise Security

Objective Continuous security monitoring and vulnerability management

```bash
# Integrate with CI/CD pipeline
python3 symbolic_hunter_complete.py build/release.exe \
    --all \
    --timeout 600 \
    -o security_scan.json

# API integration for automated scanning
curl -X POST http://security-server:5000/api/analyze \
  -F "file=@application.exe" \
  -F 'options={"verbose":true,"all_features":true}'
```

Enterprise Benefits.
- Automated security scanning in build pipeline
- Vulnerability tracking and metrics
- Integration with SIEM/SOAR platforms
- Compliance reporting

### 📚 Academic Research & Education

Objective. Teaching symbolic execution and program analysis

```bash
# Educational demonstration
python3 symbolic_hunter.py vulnerable_example.c.out \
    --find-function "buffer_overflow_demo" \
    -v

# Research experimentation
python3 symbolic_hunter.py research_binary \
    --max-states 5000 \
    --timeout 1800 \
    -o research_data.json
```

Educational Use.
- Demonstrate symbolic execution concepts
- Show real-world vulnerability discovery
- Research novel analysis techniques
- Student projects and assignments

## 🤝 Contributing

welcome contributions from the security community!

### How to Contribute

1. Fork the Repository
   ```bash
   git clone https://github.com/alishahid74/SymbolicHunter.git
   cd SymbolicHunter
   git checkout -b feature/your-feature-name
   ```

2. Make Your Changes.
   - Follow PEP 8 style guidelines
   - Add docstrings to all functions
   - Include type hints where appropriate
   - Update documentation

3. Test Your Changes
   ```bash
   # Test core functionality
   python3 symbolic_hunter.py test_binaries/sample.exe
   
   # Test web dashboard
   python3 web_dashboard.py
   
   # Test modules
   python3 -m pytest tests/  # If tests exist
   ```

4. Submit Pull Request.
   - Describe changes clearly
   - Reference related issues
   - Include before/after examples
   - Update CHANGELOG.md

### Areas for Contribution

#### High Priority
- [ ] Additional Vulnerability Patterns
  - Race conditions (TOCTOU)
  - Use-after-free detection
  - Double-free detection
  - Heap overflow patterns
  - Type confusion

- [ ] Performance Optimizations
  - Parallel state exploration
  - Better path pruning algorithms
  - Caching and memoization
  - Incremental analysis

- [ ] Architecture Support
  - ARM/ARM64 binaries
  - MIPS architecture
  - RISC-V support
  - macOS Mach-O format

#### Medium Priority
- [ ] Enhanced Web Dashboard
  - Advanced visualizations (D3.js graphs)
  - Real-time collaboration features
  - User authentication and roles
  - Analysis comparison tools
  - Dark/light theme toggle

- [ ] Additional Report Formats
  - PDF generation
  - Markdown reports
  - SARIF format
  - CSV/Excel exports

- [ ] More Signature Types
  - ClamAV signatures
  - Suricata Lua scripts
  - Custom IOC formats
  - ATT&CK mapping

- [ ] Plugin System
  - Custom analyzer plugins
  - Report format plugins
  - Integration plugins
  - Hook system for extensibility

#### Nice to Have
- [ ] Docker Containerization
  - Dockerfile for easy deployment
  - Docker Compose for full stack
  - Kubernetes manifests

- [ ] Cloud Analysis Support
  - AWS Lambda integration
  - Distributed analysis
  - Cloud storage backends

- [ ] Machine Learning Integration
  - ML-based path prioritization
  - Vulnerability classification
  - False positive reduction

- [ ] IDE Integration
  - VS Code extension
  - IDA Pro plugin
  - Ghidra plugin


### Testing Guidelines

Add tests for new features:

```python
# tests/test_vulnerability_detection.py
import pytest
from symbolic_hunter import SymbolicHunter

def test_buffer_overflow_detection():
    """Test buffer overflow detection"""
    hunter = SymbolicHunter('tests/binaries/bof_sample.exe')
    hunter.explore_binary()
    results = hunter.vulnerabilities
    
    assert 'buffer_overflow' in results
    assert len(results['buffer_overflow']) > 0
    assert results['buffer_overflow'][0]['severity'] in ['HIGH', 'CRITICAL']

def test_taint_analysis():
    """Test taint analysis functionality"""
    hunter = SymbolicHunter('tests/binaries/taint_sample.exe')
    hunter.explore_binary()
    
    assert len(hunter.taint_sinks) > 0
    assert any('system' in sink['function'] for sink in hunter.taint_sinks)

def test_exploit_generation():
    """Test exploit candidate generation"""
    hunter = SymbolicHunter('tests/binaries/exploit_sample.exe')
    hunter.explore_binary()
    
    assert len(hunter.exploit_candidates) > 0
    assert hunter.exploit_candidates[0]['input'] is not None
```

## 🙏 Credits & Acknowledgments

### Development Team

Created by. Rachel Soubier and Shahid Ali
Contributors [See CONTRIBUTORS.md]

### Built With

- [angr](https://angr.io/) - Binary analysis platform by UC Santa Barbara Computer Security Lab
- [claripy](https://github.com/angr/claripy) - Constraint solving abstraction layer
- [Z3](https://github.com/Z3Prover/z3) - Microsoft Research SMT solver
- [Flask](https://flask.palletsprojects.com/) - Python web framework
- [Socket.IO](https://socket.io/) - Real-time communication
- Python 3.8+ - Programming language


### Inspiration

SymbolicHunter was inspired by:
- Need for accessible symbolic execution tools
- Gap between academic research and practical security tools
- Real-world vulnerability discovery requirements
- CTF competition challenges
- Desire to automate binary analysis workflows

---

## ⚠️ Legal Disclaimer

### IMPORTANT: READ CAREFULLY BEFORE USING THIS TOOL

SymbolicHunter is designed for authorized security testing, research, and educational purposes ONLY.

### Authorized Use

✅ PERMITTED.
- Security research on your own systems
- Authorized penetration testing with written permission
- Academic research and education
- Analyzing malware samples in isolated environments
- CTF competitions and training exercises
- Vulnerability research with responsible disclosure
- Internal security assessments on owned systems

❌ .PROHIBITED.
- Unauthorized access to systems or networks
- Malicious use or weaponization of exploits
- Testing systems without explicit written permission
- Violating computer fraud and abuse laws (CFAA, Computer Misuse Act, etc.)
- Distributing exploits for malicious purposes
- Any illegal activities

### Liability Disclaimer

the authors.
- Are NOT responsible for any misuse of this tool
- Provide this software "AS IS" without warranty of any kind
- Make no guarantees about accuracy or completeness
- Shall not be held liable for any damages arising from use
- Do not condone or support illegal activities

### Legal Compliance

Users are responsible for.
- Obtaining proper authorization before testing ANY system
- Complying with all applicable local, state, federal, and international laws
- Following responsible disclosure practices
- Using the tool ethically and professionally
- Understanding and accepting all legal risks

### Responsible Disclosure

If you discover vulnerabilities using SymbolicHunter:

1. Report responsibly to the affected vendor/maintainer
2. Allow reasonable time for patching (typically 90 days)
3. Do not exploit vulnerabilities maliciously
4. Follow coordinated disclosure practices
5. Adhere to vendor bug bounty program rules if applicable

### Regional Laws

Be aware of relevant laws in your jurisdiction:
- USA: Computer Fraud and Abuse Act (CFAA)
- UK: Computer Misuse Act 1990
- EU: Directive on attacks against information systems
- International: Budapest Convention on Cybercrime

### Acceptable Use Agreement

By using SymbolicHunter, you agree to.
- Use it legally, ethically, and responsibly
- Obtain authorization before analyzing any system
- Not use it for malicious purposes
- Accept all legal responsibility for your actions
- Comply with all applicable laws and regulations

### Educational Use

For educational purposes:
- Use only on provided test binaries or CTF challenges
- Analyze in isolated lab environments
- Follow institution's acceptable use policies
- Cite SymbolicHunter in academic work

### Commercial Use

For commercial penetration testing:
- Obtain signed authorization from clients
- Follow industry standards (OWASP, PTES, etc.)
- Maintain professional liability insurance
- Document all activities thoroughly

---

## 📧 Support & Contact

### Getting Help

This part will be add soon.


### Third-Party Licenses

SymbolicHunter uses the following open-source projects:

- angr - BSD 2-Clause License
- claripy - BSD 2-Clause License
- Z3 - MIT License
- Flask - BSD 3-Clause License


## 🗺️ Roadmap

### Version 1.0 (Current) ✅
- ✅ Core symbolic execution engine
- ✅ Taint analysis
- ✅ Vulnerability detection (7 categories)
- ✅ HTML report generation
- ✅ Exploit testing
- ✅ Signature generation (YARA, Snort, SIGMA)
- ✅ Memory analysis
- ✅ Web dashboard with real-time updates
- ✅ RESTful API
- ✅ WebSocket support

### Version 1.5 (Q2 2025)
- 🔄 Parallel state exploration (multi-threading)
- 🔄 Enhanced path pruning algorithms
- 🔄 ARM/ARM64 binary support
- 🔄 Docker containerization
- 🔄 Advanced web UI visualizations (D3.js graphs)
- 🔄 Multi-user support with authentication
- 🔄 Analysis history and comparison tools

### Version 2.0 (Q4 2025)
- 📋 Full web-based IDE interface
- 📋 Machine learning path prioritization
- 📋 Plugin architecture for extensions
- 📋 IDA Pro / Ghidra integration
- 📋 Cloud analysis support (AWS, Azure, GCP)
- 📋 Distributed analysis clusters
- 📋 Real-time collaboration features
- 📋 Advanced diff analysis

### Future Considerations
- PDF report generation
- Automated patch generation
- Differential analysis (binary diffing)
- Multi-architecture support (MIPS, RISC-V)
- Mobile binary analysis (APK, IPA)
- Firmware analysis capabilities
- IoT device analysis
- Blockchain smart contract analysis

## ❓ FAQ

Q: What types of binaries does SymbolicHunter support?  
A: Windows PE files (.exe, .dll) and Linux ELF binaries (32-bit and 64-bit).

Q: How long does analysis typically take? 
A: From 30 seconds for quick triage to 30+ minutes for deep analysis, depending on binary complexity and settings.

Q: Can SymbolicHunter analyze obfuscated binaries?
A: Partially. Simple obfuscation is handled, but heavy packing/obfuscation may require unpacking first with tools like UPX.

Q: Does it work on macOS binaries?
A: Limited support for Mach-O format. Best results are with PE/ELF binaries.

Q: How accurate is the vulnerability detection?  
A: High precision but may have false positives. Always manually verify critical findings.

Q: Can I use this in production security tools?  
A: Yes, but test thoroughly and follow the license terms (MIT).

Q: Does it require symbols or debug info?  
A: No, works on stripped binaries, though symbols improve analysis quality.

Q: How much RAM is needed?  
A: Minimum 4GB, recommend 8GB+ for large binaries. 16GB+ for extensive analysis.

Q: Can it detect ALL vulnerability types?  
A: No tool is perfect. SymbolicHunter focuses on memory corruption and injection vulnerabilities. Use complementary tools for comprehensive coverage.

Q: Is it better than fuzzing?  
A: They're complementary. Symbolic execution finds deep paths with complex constraints; fuzzing finds surface bugs quickly. Best results come from using both.

Q: Can I contribute to the project?  
A: Absolutely! See the [Contributing](#-contributing) section for guidelines.

Q: Is commercial use allowed?  
A: Yes, under MIT license terms. For commercial support, contact us.

---

## 🌟 Star History & Community

If you find SymbolicHunter useful, please consider:

- ⭐ Starring the repository on GitHub
- 🐦 Sharing with the security community on social media
- 🤝 Contributing code, documentation, or ideas
- 📝 Writing blog posts or tutorials about your experience
- 💬 Providing feedback through issues and discussions
- 🎓 Using in educational settings and citing in research


### Related Projects
- angr. [https://angr.io](https://angr.io)
- angr Documentation. [https://docs.angr.io](https://docs.angr.io)
- claripy. [https://github.com/angr/claripy](https://github.com/angr/claripy)

---



## 🔍 Made with ❤️ for the Security Research Community

SymbolicHunter - Finding vulnerabilities before the bad guys do.

Author. Rachel soubier and Shahid Ali 
Version. 1.0.0  
License. MIT

The best defense is knowing your vulnerabilities before attackers do.

Happy Hunting! 🔍

