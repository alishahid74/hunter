#!/usr/bin/env python3
"""
Security Tool Integration Example
"""
import json
import requests
from symbolic_hunter import SymbolicHunter
from modules import *

class SecurityPipeline:
    """Integrated security analysis pipeline"""
    
    def __init__(self, siem_url=None, ti_platform_url=None):
        self.siem_url = siem_url
        self.ti_platform_url = ti_platform_url
    
    def send_to_siem(self, findings):
        """Send findings to SIEM system"""
        if not self.siem_url:
            return
        
        for finding in findings:
            event = {
                'timestamp': finding.get('timestamp', datetime.now().isoformat()),
                'severity': self._map_severity(finding),
                'category': finding.get('type', 'unknown'),
                'description': finding.get('description'),
                'source': 'SymbolicHunter',
                'binary': finding.get('binary'),
                'address': finding.get('address')
            }
            
            try:
                requests.post(
                    f"{self.siem_url}/api/events",
                    json=event,
                    timeout=5
                )
            except Exception as e:
                print(f"⚠ SIEM error: {e}")
    
    def update_threat_intel(self, iocs):
        """Update threat intelligence platform"""
        if not self.ti_platform_url:
            return
        
        for ioc in iocs:
            indicator = {
                'type': ioc['type'],
                'value': ioc['value'],
                'confidence': ioc.get('confidence', 'medium'),
                'source': 'SymbolicHunter',
                'tags': ioc.get('tags', [])
            }
            
            try:
                requests.post(
                    f"{self.ti_platform_url}/api/indicators",
                    json=indicator,
                    timeout=5
                )
            except Exception as e:
                print(f"⚠ TI platform error: {e}")
    
    def quarantine_sample(self, binary_path, risk_level):
        """Quarantine high-risk samples"""
        if risk_level in ['CRITICAL', 'HIGH']:
            quarantine_dir = '/var/quarantine/'
            os.makedirs(quarantine_dir, exist_ok=True)
            
            import shutil
            dest = os.path.join(quarantine_dir, os.path.basename(binary_path))
            shutil.move(binary_path, dest)
            
            print(f"🔒 Sample quarantined: {dest}")
            return dest
        return None
    
    def create_ticket(self, results):
        """Create security incident ticket"""
        ticket = {
            'title': f"SymbolicHunter Alert - {results['binary']}",
            'severity': results['risk_level'],
            'description': self._format_ticket_description(results),
            'assignee': 'security-team',
            'labels': ['symbolic-execution', 'vulnerability', results['risk_level'].lower()]
        }
        
        # Post to ticketing system (Jira, ServiceNow, etc.)
        print(f"🎫 Ticket created: {ticket['title']}")
        return ticket
    
    def analyze(self, binary_path):
        """Main analysis workflow with integrations"""
        
        print_banner()
        print_section("Security Pipeline Analysis")
        
        # Run SymbolicHunter
        hunter = SymbolicHunter(binary_path, verbose=True, max_states=1500, timeout=600)
        hunter.explore_binary()
        
        results = {
            'binary': binary_path,
            'statistics': hunter.stats,
            'vulnerabilities': dict(hunter.vulnerabilities),
            'taint_sinks': hunter.taint_sinks,
            'dangerous_functions': hunter.dangerous_functions,
            'exploit_candidates': hunter.exploit_candidates,
            'anti_analysis': hunter.anti_analysis_detected
        }
        
        # Risk assessment
        risk_level, _ = assess_risk_level(results)
        results['risk_level'] = risk_level
        
        # 1. Send to SIEM
        if hunter.taint_sinks:
            print_section("Sending to SIEM")
            self.send_to_siem(hunter.taint_sinks)
        
        # 2. Update threat intelligence
        if hunter.dangerous_functions:
            print_section("Updating Threat Intelligence")
            iocs = self._extract_iocs(results)
            self.update_threat_intel(iocs)
        
        # 3. Quarantine if high risk
        quarantined = self.quarantine_sample(binary_path, risk_level)
        
        # 4. Create incident ticket for critical findings
        if risk_level == 'CRITICAL':
            print_section("Creating Security Incident")
            self.create_ticket(results)
        
        # 5. Generate report
        generate_report(results, 'security_report.html')
        
        print_section("Pipeline Complete", Colors.GREEN)
        return results
    
    def _map_severity(self, finding):
        """Map finding to SIEM severity"""
        severity_map = {
            'Command Injection': 'critical',
            'Buffer Overflow': 'high',
            'Format String': 'high',
            'NULL Dereference': 'medium',
            'Integer Overflow': 'medium'
        }
        return severity_map.get(finding.get('type'), 'low')
    
    def _extract_iocs(self, results):
        """Extract IOCs from results"""
        iocs = []
        
        # File hash IOCs
        if 'hashes' in results:
            for hash_type, hash_value in results['hashes'].items():
                iocs.append({
                    'type': f'file_{hash_type}',
                    'value': hash_value,
                    'confidence': 'high'
                })
        
        # API call IOCs
        for api in results.get('dangerous_functions', []):
            iocs.append({
                'type': 'api_call',
                'value': api['name'],
                'confidence': 'medium',
                'tags': [api.get('category', 'unknown')]
            })
        
        return iocs
    
    def _format_ticket_description(self, results):
        """Format ticket description"""
        desc = f"""
## SymbolicHunter Analysis Alert

**Binary:** {results['binary']}
**Risk Level:** {results['risk_level']}

### Key Findings:
- Vulnerabilities: {sum(len(v) for v in results['vulnerabilities'].values())}
- Taint Sinks: {len(results.get('taint_sinks', []))}
- Exploit Candidates: {len(results.get('exploit_candidates', []))}
- Anti-Analysis: {len(results.get('anti_analysis', []))}

### Recommended Actions:
1. Review detailed analysis report
2. Verify findings in sandbox environment
3. Update detection signatures
4. Assess impact and remediation requirements

**Report:** security_report.html
"""
        return desc

# Usage
if __name__ == '__main__':
    pipeline = SecurityPipeline(
        siem_url='https://siem.company.com',
        ti_platform_url='https://threatintel.company.com'
    )
    
    import sys
    if len(sys.argv) < 2:
        print("Usage: python security_pipeline.py <binary>")
        sys.exit(1)
    
    pipeline.analyze(sys.argv[1])
