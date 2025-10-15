#!/usr/bin/env python3
"""
Batch Processing Pipeline for SymbolicHunter
Analyze malware datasets at scale with parallel processing and comprehensive reporting

Features:
- Download samples from MalwareBazaar
- Parallel processing with resource management
- Automatic clustering and family detection
- Comprehensive reporting and statistics
- Integration with VirusTotal (optional)
"""

import os
import sys
import json
import hashlib
import argparse
import shutil
import zipfile
import tempfile
from pathlib import Path
from datetime import datetime, timedelta
from typing import List, Dict, Any, Tuple, Optional
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from collections import defaultdict
import time
import requests
import subprocess

# For data processing
import pandas as pd
import numpy as np

# Progress bar
try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False
    print("[!] Install tqdm for progress bars: pip install tqdm")

# =====================================
# Configuration
# =====================================
class Config:
    """Configuration settings for batch processing"""
    
    # MalwareBazaar API
    BAZAAR_API_URL = "https://mb-api.abuse.ch/api/v1/"
    BAZAAR_DOWNLOAD_URL = "https://bazaar.abuse.ch/download/"
    
    # VirusTotal API (optional - requires API key)
    VT_API_KEY = os.environ.get("VT_API_KEY", "")
    VT_API_URL = "https://www.virustotal.com/api/v3/"
    
    # Processing settings
    MAX_WORKERS = os.cpu_count() or 4
    MEMORY_LIMIT_PER_WORKER = 4 * 1024**3  # 4GB per worker
    TIMEOUT_PER_SAMPLE = 300  # 5 minutes per sample
    MAX_STATES = 1000
    
    # Output settings
    REPORT_FORMAT = "html"  # html, json, csv
    KEEP_TEMP_FILES = False
    
    # Sample selection
    MAX_SAMPLES = 100  # Maximum samples to download
    SAMPLE_AGE_DAYS = 7  # Get samples from last N days
    MIN_FILE_SIZE = 1024  # Minimum file size in bytes
    MAX_FILE_SIZE = 50 * 1024 * 1024  # Maximum file size (50MB)


# =====================================
# MalwareBazaar Integration
# =====================================
class MalwareBazaarClient:
    """Client for downloading malware samples from MalwareBazaar"""
    
    def __init__(self, config: Config):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'SymbolicHunter/1.0'
        })
        
    def search_recent_samples(self, limit: int = 100) -> List[Dict]:
        """Search for recent malware samples"""
        try:
            # Get samples from last N days
            response = self.session.post(
                self.config.BAZAAR_API_URL,
                data={
                    'query': 'get_recent',
                    'selector': str(self.config.SAMPLE_AGE_DAYS * 24)  # hours
                }
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('query_status') == 'ok':
                    samples = data.get('data', [])[:limit]
                    print(f"[+] Found {len(samples)} recent samples")
                    return samples
            
            print("[!] Failed to search samples from MalwareBazaar")
            return []
            
        except Exception as e:
            print(f"[!] Error searching samples: {e}")
            return []
    
    def download_sample(self, sha256: str, output_path: Path) -> bool:
        """Download a specific sample by SHA256"""
        try:
            # Download with password 'infected'
            response = self.session.get(
                f"{self.config.BAZAAR_DOWNLOAD_URL}{sha256}/",
                stream=True
            )
            
            if response.status_code == 200:
                # Save as zip file
                zip_path = output_path.with_suffix('.zip')
                with open(zip_path, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        f.write(chunk)
                
                # Extract with password
                try:
                    with zipfile.ZipFile(zip_path, 'r') as z:
                        z.extractall(output_path.parent, pwd=b'infected')
                    
                    # Rename extracted file
                    extracted = list(output_path.parent.glob(f"{sha256}*"))[0]
                    extracted.rename(output_path)
                    
                    # Clean up zip
                    zip_path.unlink()
                    return True
                    
                except Exception as e:
                    print(f"[!] Failed to extract {sha256}: {e}")
                    return False
                    
            return False
            
        except Exception as e:
            print(f"[!] Error downloading {sha256}: {e}")
            return False
    
    def get_sample_info(self, sha256: str) -> Optional[Dict]:
        """Get detailed information about a sample"""
        try:
            response = self.session.post(
                self.config.BAZAAR_API_URL,
                data={
                    'query': 'get_info',
                    'hash': sha256
                }
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('query_status') == 'ok':
                    return data.get('data', [{}])[0]
                    
            return None
            
        except Exception:
            return None


# =====================================
# VirusTotal Integration (Optional)
# =====================================
class VirusTotalClient:
    """Client for VirusTotal API integration"""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({
            'x-apikey': api_key,
            'Accept': 'application/json'
        })
        
    def get_file_report(self, sha256: str) -> Optional[Dict]:
        """Get VirusTotal report for a file"""
        if not self.api_key:
            return None
            
        try:
            response = self.session.get(
                f"https://www.virustotal.com/api/v3/files/{sha256}"
            )
            
            if response.status_code == 200:
                return response.json()
            
            return None
            
        except Exception:
            return None


# =====================================
# Sample Processor
# =====================================
class SampleProcessor:
    """Process individual malware samples"""
    
    def __init__(self, config: Config, output_dir: Path):
        self.config = config
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
    def process_sample(self, sample_path: Path, metadata: Dict = None) -> Dict:
        """Process a single malware sample"""
        result = {
            'sample_path': str(sample_path),
            'sample_name': sample_path.name,
            'sha256': self._calculate_sha256(sample_path),
            'timestamp': datetime.now().isoformat(),
            'metadata': metadata or {},
            'status': 'pending'
        }
        
        try:
            # Run SymbolicHunter
            analysis_result = self._run_symbolic_hunter(sample_path)
            
            if analysis_result:
                result.update(analysis_result)
                result['status'] = 'success'
            else:
                result['status'] = 'failed'
                result['error'] = 'Analysis failed'
                
        except Exception as e:
            result['status'] = 'error'
            result['error'] = str(e)
            
        return result
    
    def _calculate_sha256(self, file_path: Path) -> str:
        """Calculate SHA256 hash of file"""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    
    def _run_symbolic_hunter(self, sample_path: Path) -> Optional[Dict]:
        """Run SymbolicHunter on sample"""
        try:
            # Prepare output file
            output_file = self.output_dir / f"{sample_path.stem}_analysis.json"
            
            # Build command
            cmd = [
                sys.executable,
                "symbolic_hunter_enhanced.py",
                str(sample_path),
                "--output", str(output_file),
                "--max-states", str(self.config.MAX_STATES),
                "--timeout", str(self.config.TIMEOUT_PER_SAMPLE),
                "--memory-limit", f"{self.config.MEMORY_LIMIT_PER_WORKER // 1024**3}G",
                "--anti-evasion"
            ]
            
            # Run analysis with timeout
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.config.TIMEOUT_PER_SAMPLE + 60  # Extra time for cleanup
            )
            
            # Load results if successful
            if output_file.exists():
                with open(output_file, 'r') as f:
                    return json.load(f)
                    
            return None
            
        except subprocess.TimeoutExpired:
            return {'error': 'Analysis timeout'}
        except Exception as e:
            return {'error': str(e)}


# =====================================
# Batch Processor
# =====================================
class BatchProcessor:
    """Orchestrate batch processing of malware samples"""
    
    def __init__(self, config: Config):
        self.config = config
        self.bazaar_client = MalwareBazaarClient(config)
        self.vt_client = VirusTotalClient(config.VT_API_KEY) if config.VT_API_KEY else None
        self.results = []
        self.start_time = None
        
    def download_samples(self, output_dir: Path, limit: int = 100) -> List[Path]:
        """Download samples from MalwareBazaar"""
        print(f"\n[*] Downloading samples from MalwareBazaar...")
        
        samples_dir = output_dir / "samples"
        samples_dir.mkdir(parents=True, exist_ok=True)
        
        # Search for recent samples
        samples = self.bazaar_client.search_recent_samples(limit)
        
        if not samples:
            print("[!] No samples found")
            return []
            
        downloaded = []
        
        # Download with progress bar
        iterator = tqdm(samples, desc="Downloading") if HAS_TQDM else samples
        
        for sample in iterator:
            sha256 = sample.get('sha256_hash')
            if not sha256:
                continue
                
            # Check file size
            file_size = sample.get('file_size', 0)
            if file_size < self.config.MIN_FILE_SIZE or file_size > self.config.MAX_FILE_SIZE:
                continue
                
            # Download sample
            sample_path = samples_dir / f"{sha256}.exe"
            if self.bazaar_client.download_sample(sha256, sample_path):
                downloaded.append(sample_path)
                
                # Save metadata
                metadata_path = sample_path.with_suffix('.meta.json')
                with open(metadata_path, 'w') as f:
                    json.dump(sample, f, indent=2)
                    
            # Rate limiting
            time.sleep(1)
            
            if len(downloaded) >= limit:
                break
                
        print(f"[+] Downloaded {len(downloaded)} samples")
        return downloaded
    
    def process_samples(self, sample_paths: List[Path], output_dir: Path) -> List[Dict]:
        """Process samples in parallel"""
        print(f"\n[*] Processing {len(sample_paths)} samples with {self.config.MAX_WORKERS} workers...")
        
        processor = SampleProcessor(self.config, output_dir / "analysis")
        results = []
        
        # Use ProcessPoolExecutor for parallel processing
        with ProcessPoolExecutor(max_workers=self.config.MAX_WORKERS) as executor:
            # Submit all tasks
            futures = {}
            for sample_path in sample_paths:
                # Load metadata if available
                metadata = {}
                metadata_path = sample_path.with_suffix('.meta.json')
                if metadata_path.exists():
                    with open(metadata_path, 'r') as f:
                        metadata = json.load(f)
                        
                future = executor.submit(processor.process_sample, sample_path, metadata)
                futures[future] = sample_path
                
            # Process completed tasks
            iterator = tqdm(as_completed(futures), total=len(futures), desc="Processing") if HAS_TQDM else as_completed(futures)
            
            for future in iterator:
                try:
                    result = future.result(timeout=self.config.TIMEOUT_PER_SAMPLE + 120)
                    results.append(result)
                    
                    # Enrich with VirusTotal data if available
                    if self.vt_client and result.get('sha256'):
                        vt_report = self.vt_client.get_file_report(result['sha256'])
                        if vt_report:
                            result['virustotal'] = {
                                'detection_ratio': f"{vt_report.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0)}/70",
                                'reputation': vt_report.get('data', {}).get('attributes', {}).get('reputation', 0)
                            }
                            
                except Exception as e:
                    sample_path = futures[future]
                    results.append({
                        'sample_path': str(sample_path),
                        'status': 'error',
                        'error': str(e)
                    })
                    
        return results
    
    def generate_report(self, results: List[Dict], output_dir: Path):
        """Generate comprehensive batch processing report"""
        print(f"\n[*] Generating reports...")
        
        report_dir = output_dir / "reports"
        report_dir.mkdir(parents=True, exist_ok=True)
        
        # Calculate statistics
        total = len(results)
        successful = sum(1 for r in results if r.get('status') == 'success')
        failed = sum(1 for r in results if r.get('status') == 'failed')
        errors = sum(1 for r in results if r.get('status') == 'error')
        
        # Aggregate metrics
        metrics = {
            'total_samples': total,
            'successful': successful,
            'failed': failed,
            'errors': errors,
            'success_rate': (successful / total * 100) if total > 0 else 0,
            'total_time': (datetime.now() - self.start_time).total_seconds() if self.start_time else 0,
            'avg_time_per_sample': ((datetime.now() - self.start_time).total_seconds() / total) if (self.start_time and total > 0) else 0,
        }
        
        # Vulnerability summary
        vuln_summary = defaultdict(int)
        malware_families = defaultdict(int)
        
        for result in results:
            if result.get('status') == 'success':
                # Count vulnerabilities
                vulns = result.get('vulnerabilities', {})
                for vuln_type, instances in vulns.items():
                    vuln_summary[vuln_type] += len(instances) if isinstance(instances, list) else 0
                    
                # Count malware indicators
                malware = result.get('malware_analysis', {})
                if malware.get('ransomware_risk', 0) > 60:
                    malware_families['ransomware'] += 1
                if malware.get('cryptomining_risk', 0) > 60:
                    malware_families['cryptominer'] += 1
                if malware.get('packed'):
                    malware_families['packed'] += 1
                    
        # Create summary report
        summary_report = {
            'timestamp': datetime.now().isoformat(),
            'metrics': metrics,
            'vulnerability_summary': dict(vuln_summary),
            'malware_families': dict(malware_families),
            'samples': results
        }
        
        # Save JSON report
        json_path = report_dir / "batch_report.json"
        with open(json_path, 'w') as f:
            json.dump(summary_report, f, indent=2)
        print(f"[+] JSON report saved to: {json_path}")
        
        # Generate HTML report
        self._generate_html_report(summary_report, report_dir / "batch_report.html")
        
        # Generate CSV for easy analysis
        self._generate_csv_report(results, report_dir / "batch_results.csv")
        
    def _generate_html_report(self, report: Dict, output_path: Path):
        """Generate HTML report"""
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>SymbolicHunter Batch Processing Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
                .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                         color: white; padding: 30px; border-radius: 10px; margin-bottom: 30px; }
                h1 { margin: 0; }
                .metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); 
                          gap: 20px; margin-bottom: 30px; }
                .metric-card { background: white; padding: 20px; border-radius: 10px; 
                              box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                .metric-value { font-size: 2em; font-weight: bold; color: #667eea; }
                .metric-label { color: #666; margin-top: 5px; }
                table { width: 100%; background: white; border-collapse: collapse; 
                       border-radius: 10px; overflow: hidden; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                th { background: #667eea; color: white; padding: 15px; text-align: left; }
                td { padding: 12px; border-bottom: 1px solid #eee; }
                tr:hover { background: #f9f9f9; }
                .success { color: #4caf50; font-weight: bold; }
                .failed { color: #f44336; font-weight: bold; }
                .warning { color: #ff9800; font-weight: bold; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🔍 SymbolicHunter Batch Processing Report</h1>
                <p>Generated: {timestamp}</p>
            </div>
            
            <div class="metrics">
                <div class="metric-card">
                    <div class="metric-value">{total_samples}</div>
                    <div class="metric-label">Total Samples</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value" class="success">{successful}</div>
                    <div class="metric-label">Successful</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value" class="warning">{failed}</div>
                    <div class="metric-label">Failed</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">{success_rate:.1f}%</div>
                    <div class="metric-label">Success Rate</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">{total_time:.1f}s</div>
                    <div class="metric-label">Total Time</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">{avg_time:.1f}s</div>
                    <div class="metric-label">Avg Time/Sample</div>
                </div>
            </div>
            
            <h2>Vulnerability Summary</h2>
            <table>
                <tr><th>Vulnerability Type</th><th>Count</th></tr>
                {vuln_rows}
            </table>
            
            <h2 style="margin-top: 30px;">Malware Classification</h2>
            <table>
                <tr><th>Category</th><th>Count</th></tr>
                {malware_rows}
            </table>
            
            <h2 style="margin-top: 30px;">Sample Results</h2>
            <table>
                <tr>
                    <th>Sample</th>
                    <th>Status</th>
                    <th>Vulnerabilities</th>
                    <th>Ransomware Risk</th>
                    <th>Mining Risk</th>
                    <th>Time (s)</th>
                </tr>
                {sample_rows}
            </table>
        </body>
        </html>
        """
        
        # Build vulnerability rows
        vuln_rows = ""
        for vuln_type, count in report['vulnerability_summary'].items():
            vuln_rows += f"<tr><td>{vuln_type.replace('_', ' ').title()}</td><td>{count}</td></tr>"
            
        # Build malware rows
        malware_rows = ""
        for category, count in report['malware_families'].items():
            malware_rows += f"<tr><td>{category.title()}</td><td>{count}</td></tr>"
            
        # Build sample rows
        sample_rows = ""
        for sample in report['samples'][:100]:  # Limit to first 100
            status_class = sample.get('status', 'unknown')
            if status_class == 'success':
                status_class = 'success'
            elif status_class == 'failed':
                status_class = 'failed'
            else:
                status_class = 'warning'
                
            sample_rows += f"""
            <tr>
                <td>{Path(sample.get('sample_path', '')).name}</td>
                <td class="{status_class}">{sample.get('status', 'unknown').upper()}</td>
                <td>{sum(len(v) for v in sample.get('vulnerabilities', {}).values() if isinstance(v, list))}</td>
                <td>{sample.get('malware_analysis', {}).get('ransomware_risk', 0)}</td>
                <td>{sample.get('malware_analysis', {}).get('cryptomining_risk', 0)}</td>
                <td>{sample.get('statistics', {}).get('time_elapsed', 0):.1f}</td>
            </tr>
            """
            
        # Fill template
        html = html_template.format(
            timestamp=report['timestamp'],
            total_samples=report['metrics']['total_samples'],
            successful=report['metrics']['successful'],
            failed=report['metrics']['failed'],
            success_rate=report['metrics']['success_rate'],
            total_time=report['metrics']['total_time'],
            avg_time=report['metrics']['avg_time_per_sample'],
            vuln_rows=vuln_rows,
            malware_rows=malware_rows,
            sample_rows=sample_rows
        )
        
        with open(output_path, 'w') as f:
            f.write(html)
        print(f"[+] HTML report saved to: {output_path}")
        
    def _generate_csv_report(self, results: List[Dict], output_path: Path):
        """Generate CSV report for easy analysis"""
        rows = []
        
        for result in results:
            row = {
                'sample': Path(result.get('sample_path', '')).name,
                'sha256': result.get('sha256', ''),
                'status': result.get('status', ''),
                'paths_explored': result.get('statistics', {}).get('paths_explored', 0),
                'code_coverage': result.get('statistics', {}).get('code_coverage', 0),
                'time_elapsed': result.get('statistics', {}).get('time_elapsed', 0),
                'vuln_count': sum(len(v) for v in result.get('vulnerabilities', {}).values() if isinstance(v, list)),
                'ransomware_risk': result.get('malware_analysis', {}).get('ransomware_risk', 0),
                'cryptomining_risk': result.get('malware_analysis', {}).get('cryptomining_risk', 0),
                'packed': result.get('malware_analysis', {}).get('packed', False),
                'evasion_techniques': len(result.get('malware_analysis', {}).get('evasion_techniques', [])),
            }
            rows.append(row)
            
        df = pd.DataFrame(rows)
        df.to_csv(output_path, index=False)
        print(f"[+] CSV report saved to: {output_path}")
        
    def run(self, mode: str = 'download', input_dir: Path = None, output_dir: Path = None):
        """Run batch processing pipeline"""
        self.start_time = datetime.now()
        
        output_dir = output_dir or Path("batch_analysis")
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Get samples
        if mode == 'download':
            # Download from MalwareBazaar
            sample_paths = self.download_samples(output_dir, self.config.MAX_SAMPLES)
        else:
            # Use local samples
            if not input_dir or not input_dir.exists():
                print("[!] Input directory not found")
                return
                
            sample_paths = list(input_dir.glob("*"))
            sample_paths = [p for p in sample_paths if p.is_file() and p.suffix in ['.exe', '.dll', '.bin', '']]
            print(f"[+] Found {len(sample_paths)} local samples")
            
        if not sample_paths:
            print("[!] No samples to process")
            return
            
        # Process samples
        results = self.process_samples(sample_paths, output_dir)
        
        # Generate report
        self.generate_report(results, output_dir)
        
        # Clean up temp files if configured
        if not self.config.KEEP_TEMP_FILES:
            temp_dir = output_dir / "temp"
            if temp_dir.exists():
                shutil.rmtree(temp_dir)
                
        elapsed = (datetime.now() - self.start_time).total_seconds()
        print(f"\n[+] Batch processing complete in {elapsed:.1f} seconds")
        print(f"[+] Results saved to: {output_dir}")


# =====================================
# Main Execution
# =====================================
def main():
    parser = argparse.ArgumentParser(
        description="Batch Processing Pipeline for SymbolicHunter",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Download and analyze samples from MalwareBazaar
  %(prog)s --mode download --limit 50 --output malware_batch
  
  # Analyze local malware samples
  %(prog)s --mode local --input /path/to/samples --output analysis_results
  
  # Parallel processing with 8 workers
  %(prog)s --mode download --workers 8 --limit 100
  
  # Integration with VirusTotal
  export VT_API_KEY=your_api_key
  %(prog)s --mode download --vt-enrich
        """
    )
    
    parser.add_argument("--mode", choices=['download', 'local'], default='download',
                       help="Processing mode")
    parser.add_argument("--input", type=Path, help="Input directory for local mode")
    parser.add_argument("--output", type=Path, default=Path("batch_analysis"),
                       help="Output directory")
    parser.add_argument("--limit", type=int, default=100,
                       help="Maximum samples to process")
    parser.add_argument("--workers", type=int, default=Config.MAX_WORKERS,
                       help="Number of parallel workers")
    parser.add_argument("--timeout", type=int, default=Config.TIMEOUT_PER_SAMPLE,
                       help="Timeout per sample (seconds)")
    parser.add_argument("--memory-limit", type=int, default=4,
                       help="Memory limit per worker (GB)")
    parser.add_argument("--vt-enrich", action="store_true",
                       help="Enrich results with VirusTotal data")
    parser.add_argument("--keep-temp", action="store_true",
                       help="Keep temporary files")
    
    args = parser.parse_args()
    
    # Configure
    config = Config()
    config.MAX_SAMPLES = args.limit
    config.MAX_WORKERS = args.workers
    config.TIMEOUT_PER_SAMPLE = args.timeout
    config.MEMORY_LIMIT_PER_WORKER = args.memory_limit * 1024**3
    config.KEEP_TEMP_FILES = args.keep_temp
    
    if args.vt_enrich and not config.VT_API_KEY:
        print("[!] VirusTotal API key not found. Set VT_API_KEY environment variable.")
        
    # Print configuration
    print("="*60)
    print("SymbolicHunter Batch Processing Pipeline")
    print("="*60)
    print(f"Mode: {args.mode}")
    print(f"Workers: {config.MAX_WORKERS}")
    print(f"Memory per worker: {config.MEMORY_LIMIT_PER_WORKER // 1024**3}GB")
    print(f"Timeout per sample: {config.TIMEOUT_PER_SAMPLE}s")
    print(f"Output directory: {args.output}")
    print("="*60)
    
    # Run batch processor
    processor = BatchProcessor(config)
    processor.run(mode=args.mode, input_dir=args.input, output_dir=args.output)


if __name__ == "__main__":
    main()
