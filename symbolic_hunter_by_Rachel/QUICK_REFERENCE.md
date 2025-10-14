# SymbolicHunter Quick Reference 🚀 Cheat Sheet

## One-Liners

```bash
# Full analysis with everything
python symbolic_hunter_complete.py malware.exe --all -v

# Quick triage (30 seconds)
python symbolic_hunter.py suspicious.exe --timeout 30

# Deep dive (10 minutes)
python symbolic_hunter.py target.exe -v --max-states 5000 --timeout 600

# Generate HTML report only
python symbolic_hunter_complete.py binary.exe --html-report report.html

# Test exploits automatically
python symbolic_hunter_complete.py binary.exe --test-exploits -v

# Create detection signatures
python symbolic_hunter_complete.py binary.exe --generate-signatures

# Everything + output directory
python symbolic_hunter_complete.py binary.exe --all -v --output-dir results/
```

## File Structure Setup

```bash
# Quick setup
chmod +x setup.sh && ./setup.sh

# Manual setup
mkdir -p modules templates output signatures
touch modules/__init__.py
```

## Common Workflows

### 🔍 Malware Analysis
```bash
# Step 1: Basic info
file malware.exe
strings malware.exe | grep -i "http\|cmd\|powershell"

# Step 2: Full analysis
python symbolic_hunter_complete.py malware.exe --all -v --output-dir malware_analysis/

# Step 3: Review results
firefox malware_analysis/report.html
cat malware_analysis/signatures/malware.exe.yar
```

### 🎯 CTF Challenge
```bash
# Find path to win() function
python symbolic_hunter.py challenge.bin --find-function "win" -v

# Get flag input
python symbolic_hunter.py challenge.bin --poc exploit.py
python3 exploit.py
```

### 🛡️ Vulnerability Research
```bash
# Deep analysis
python symbolic_hunter.py target.exe -v \
    --max-states 10000 \
    --timeout 1800 \
    -o vuln_report.json

# Test findings
python symbolic_hunter_complete.py target.exe --test-exploits

# Create signatures
python symbolic_hunter_complete.py target.exe --generate-signatures
```

### 📊 Batch Processing
```bash
# Analyze multiple files
for file in samples/*.exe; do
    echo "[*] Analyzing $file"
    python symbolic_hunter_complete.py "$file" --all --output-dir "results/$(basename $file)"
done
```

## Module Usage

### Python API

```python
# Import modules
from modules import *

# HTML Report
generate_report(results, 'report.html')

# Test Exploits
test_results = test_exploits(binary, exploits)

# Generate Signatures
sigs = generate_signatures(binary, results, 'sigs/')

# Memory Analysis
findings = analyze_memory(binary_path=binary)

# Utilities
hashes = calculate_hashes(binary)
risk, color = assess_risk_level(results)
```

## Output Files

```
results/
├── report.html              # Interactive HTML report
├── analysis.json            # Full JSON results
├── exploit_tests.json       # Exploit test results
├── memory_analysis.json     # Memory findings
├── exploits.py              # PoC scripts
└── signatures/
    ├── binary.yar          # YARA rule
    ├── binary.rules        # Snort rule
    ├── binary.yml          # SIGMA rule
    └── binary_iocs.txt     # IOC list
```

## Key Findings to Look For

### 🚨 Critical
- Taint sinks found
- Unconstrained execution
- Anti-analysis detected
- Command injection paths

### ⚠️ High
- Buffer overflows (100+)
- Exploit candidates generated
- Dangerous API calls (VirtualProtect, LoadLibrary)

### 📊 Medium
- NULL dereferences
- Format string vulnerabilities
- Low code coverage (<10%)

## Performance Tips

```bash
# Fast scan
--max-states 500 --timeout 60

# Balanced
--max-states 1000 --timeout 300

# Deep analysis
--max-states 5000 --timeout 1800

# Extreme (research)
--max-states 20000 --timeout 3600
```

## Debugging

```bash
# Verbose output
python symbolic_hunter.py binary.exe -v

# Super verbose (angr logs)
python symbolic_hunter.py binary.exe -v 2>&1 | tee analysis.log

# Check specific function
python symbolic_hunter.py binary.exe --find-function "strcpy" -v
```

## Integration Examples

### With IDA Pro
```python
# Export from IDA
import json
with open('ida_functions.json', 'w') as f:
    json.dump(Functions(), f)

# Import in SymbolicHunter
# Use for targeted analysis
```

### With Ghidra
```bash
# Export Ghidra analysis
# Import in SymbolicHunter for correlation
```

### With YARA
```bash
# Generate signature
python symbolic_hunter_complete.py malware.exe --generate-signatures

# Test signature
yara signatures/malware.exe.yar samples/
```

### With Snort
```bash
# Generate rule
python symbolic_hunter_complete.py malware.exe --generate-signatures

# Deploy rule
sudo cp signatures/malware.exe.rules /etc/snort/rules/
sudo snort -c /etc/snort/snort.conf -T
```

## Shortcuts

### Environment Variables
```bash
export SYMBOLIC_HUNTER_TIMEOUT=600
export SYMBOLIC_HUNTER_MAX_STATES=2000
```

### Aliases
```bash
alias sh-quick='python symbolic_hunter.py --timeout 30'
alias sh-full='python symbolic_hunter_complete.py --all -v'
alias sh-report='python symbolic_hunter_complete.py --html-report'
```

## Error Solutions

| Error | Solution |
|-------|----------|
| `ImportError: No module named 'angr'` | `pip install angr` |
| `AttributeError: 'CFGFast' object...` | Update angr: `pip install -U angr` |
| `Analysis timeout` | Increase `--timeout` value |
| `No vulnerabilities found` | Increase `--max-states` |
| `Module not found` | Run `./setup.sh` |

## Tips & Tricks

✅ **Always run with -v first** to see what's happening

✅ **Start with low timeout** for quick triage

✅ **Use --find-function** for targeted analysis

✅ **Export to JSON** for later processing

✅ **Generate HTML reports** for presentations

✅ **Test exploits** to confirm vulnerabilities

✅ **Create signatures** for detection

## Hotkeys (in interactive mode)

- `Ctrl+C` - Stop analysis gracefully
- `Ctrl+Z` - Pause (then `fg` to resume)

## Resources

- [angr Documentation](https://docs.angr.io/)
- [YARA Documentation](https://yara.readthedocs.io/)
- [Snort Documentation](https://www.snort.org/documents)

---

**Pro Tip:** Bookmark this page for quick reference! 📌
