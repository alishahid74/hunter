#!/bin/bash
# SymbolicHunter Setup Script
# Quickly sets up the project structure

echo "🔍 Setting up SymbolicHunter..."

# Create directory structure
echo "[*] Creating directory structure..."
mkdir -p modules
mkdir -p templates
mkdir -p output
mkdir -p signatures

# Create __init__.py if it doesn't exist
if [ ! -f "modules/__init__.py" ]; then
    echo "[*] Creating modules/__init__.py..."
    cat > modules/__init__.py << 'EOF'
"""
SymbolicHunter Modules
"""

from .reporting import ReportGenerator, generate_report
from .exploit_tester import ExploitTester, test_exploits
from .signature_gen import SignatureGenerator, generate_signatures
from .memory_analyzer import MemoryAnalyzer, analyze_memory
from .utils import *

__all__ = [
    'ReportGenerator',
    'generate_report',
    'ExploitTester',
    'test_exploits',
    'SignatureGenerator',
    'generate_signatures',
    'MemoryAnalyzer',
    'analyze_memory',
]
EOF
fi

# Create README
echo "[*] Creating README.md..."
cat > README.md << 'EOF'
# SymbolicHunter 🔍

Advanced Binary Analysis Framework with Symbolic Execution

## Features

- ✅ Symbolic Execution with angr
- ✅ Taint Analysis
- ✅ Vulnerability Detection
- ✅ Exploit Generation
- ✅ HTML Report Generation
- ✅ Automatic Exploit Testing
- ✅ YARA/Snort/SIGMA Signature Generation
- ✅ Memory Dump Analysis

## Installation

```bash
pip install angr claripy
./setup.sh
```

## Usage

```bash
# Full analysis
python symbolic_hunter_complete.py binary.exe --all -v

# HTML report only
python symbolic_hunter_complete.py binary.exe --html-report report.html

# Test exploits
python symbolic_hunter_complete.py binary.exe --test-exploits

# Generate signatures
python symbolic_hunter_complete.py binary.exe --generate-signatures
```

## Project Structure

```
SymbolicHunter/
├── symbolic_hunter.py          # Core analysis tool
├── symbolic_hunter_complete.py # Integrated tool with all features
├── config.py                   # Configuration
├── modules/
│   ├── reporting.py           # HTML report generation
│   ├── exploit_tester.py      # Exploit testing
│   ├── signature_gen.py       # Signature generation
│   ├── memory_analyzer.py     # Memory analysis
│   └── utils.py               # Utilities
├── output/                     # Analysis results
└── signatures/                 # Generated signatures
```


echo "[+] Setup complete!"
echo ""
echo "📁 Project structure:"
echo "  - modules/         (Place all module files here)"
echo "  - output/          (Analysis results)"
echo "  - signatures/      (Generated signatures)"
echo "  - templates/       (HTML templates)"
echo ""
echo "🚀 Quick start:"
echo "  1. Place all module .py files in modules/"
echo "  2. Run: python symbolic_hunter_complete.py binary.exe --all -v"
echo ""
echo "✨ Done!"
