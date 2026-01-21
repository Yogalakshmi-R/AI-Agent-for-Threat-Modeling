import json
import xml.etree.ElementTree as ET
import csv
import os
from typing import Dict, List, Any, Optional
from datetime import datetime

class QualysScanParser:
    """Parser for Qualys WAS/VMDR scan reports"""
    
    @staticmethod
    def parse_json_report(filepath: str) -> List[Dict[str, Any]]:
        """Parse Qualys JSON report format"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            findings = []
            
            # Handle different Qualys JSON structures
            vulnerabilities = (
                data.get('vulnerabilities', []) or 
                data.get('WAS_WEBAPP_REPORT', {}).get('vulnerabilities', []) or
                data.get('results', [])
            )
            
            for vuln in vulnerabilities:
                finding = {
                    'source': 'Qualys',
                    'title': vuln.get('name') or vuln.get('title') or vuln.get('vulnerability_name'),
                    'severity': QualysScanParser._normalize_severity(vuln.get('severity')),
                    'location': vuln.get('url') or vuln.get('uri') or vuln.get('location'),
                    'description': vuln.get('description') or vuln.get('details'),
                    'remediation': vuln.get('solution') or vuln.get('remediation') or vuln.get('fix'),
                    'cvss_score': vuln.get('cvss_score') or vuln.get('cvss'),
                    'cve_id': vuln.get('cve_id') or vuln.get('cve'),
                    'category': vuln.get('category') or vuln.get('type'),
                    'first_detected': vuln.get('first_detected') or vuln.get('detection_date'),
                    'last_detected': vuln.get('last_detected') or vuln.get('last_seen'),
                    'status': vuln.get('status', 'Active')
                }
                findings.append(finding)
                
            return findings
            
        except Exception as e:
            print(f"Error parsing Qualys JSON report: {e}")
            return []
    
    @staticmethod
    def parse_xml_report(filepath: str) -> List[Dict[str, Any]]:
        """Parse Qualys XML report format"""
        try:
            tree = ET.parse(filepath)
            root = tree.getroot()
            findings = []
            
            # Handle different XML structures
            for vuln in root.findall('.//VULNERABILITY') or root.findall('.//vulnerability'):
                finding = {
                    'source': 'Qualys',
                    'title': QualysScanParser._get_xml_text(vuln, ['TITLE', 'NAME', 'title', 'name']),
                    'severity': QualysScanParser._normalize_severity(
                        QualysScanParser._get_xml_text(vuln, ['SEVERITY', 'severity'])
                    ),
                    'location': QualysScanParser._get_xml_text(vuln, ['URL', 'URI', 'url', 'uri']),
                    'description': QualysScanParser._get_xml_text(vuln, ['DESCRIPTION', 'DETAILS', 'description']),
                    'remediation': QualysScanParser._get_xml_text(vuln, ['SOLUTION', 'REMEDIATION', 'solution']),
                    'cvss_score': QualysScanParser._get_xml_text(vuln, ['CVSS_SCORE', 'cvss_score']),
                    'cve_id': QualysScanParser._get_xml_text(vuln, ['CVE_ID', 'cve_id']),
                    'category': QualysScanParser._get_xml_text(vuln, ['CATEGORY', 'TYPE', 'category']),
                    'status': QualysScanParser._get_xml_text(vuln, ['STATUS', 'status']) or 'Active'
                }
                findings.append(finding)
                
            return findings
            
        except Exception as e:
            print(f"Error parsing Qualys XML report: {e}")
            return []
    
    @staticmethod
    def parse_csv_report(filepath: str) -> List[Dict[str, Any]]:
        """Parse Qualys CSV report format"""
        try:
            findings = []
            with open(filepath, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                
                for row in reader:
                    # Map common CSV column names
                    finding = {
                        'source': 'Qualys',
                        'title': row.get('Vulnerability') or row.get('Name') or row.get('Title'),
                        'severity': QualysScanParser._normalize_severity(row.get('Severity')),
                        'location': row.get('URL') or row.get('Location') or row.get('Host'),
                        'description': row.get('Description') or row.get('Details'),
                        'remediation': row.get('Solution') or row.get('Remediation'),
                        'cvss_score': row.get('CVSS Score') or row.get('CVSS'),
                        'cve_id': row.get('CVE ID') or row.get('CVE'),
                        'category': row.get('Category') or row.get('Type'),
                        'status': row.get('Status', 'Active')
                    }
                    findings.append(finding)
                    
            return findings
            
        except Exception as e:
            print(f"Error parsing Qualys CSV report: {e}")
            return []
    
    @staticmethod
    def _normalize_severity(severity: str) -> str:
        """Normalize severity levels across different formats"""
        if not severity:
            return 'Unknown'
        
        severity = str(severity).upper()
        severity_map = {
            '5': 'Critical', 'CRITICAL': 'Critical',
            '4': 'High', 'HIGH': 'High',
            '3': 'Medium', 'MEDIUM': 'Medium', 'MODERATE': 'Medium',
            '2': 'Low', 'LOW': 'Low',
            '1': 'Info', 'INFO': 'Info', 'INFORMATIONAL': 'Info'
        }
        
        return severity_map.get(severity, severity.title())
    
    @staticmethod
    def _get_xml_text(element, tag_names: List[str]) -> Optional[str]:
        """Get text from XML element using multiple possible tag names"""
        for tag in tag_names:
            elem = element.find(tag)
            if elem is not None and elem.text:
                return elem.text.strip()
        return None


class SonarQubeScanParser:
    """Parser for SonarQube scan reports"""
    
    @staticmethod
    def parse_json_report(filepath: str) -> List[Dict[str, Any]]:
        """Parse SonarQube JSON report format"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            findings = []
            
            # Handle SonarQube issues format
            issues = data.get('issues', []) or data.get('components', [])
            
            for issue in issues:
                # Extract issue details
                rule_key = issue.get('rule') or issue.get('ruleKey', '')
                severity = SonarQubeScanParser._normalize_severity(issue.get('severity'))
                
                finding = {
                    'source': 'SonarQube',
                    'title': issue.get('message') or rule_key,
                    'severity': severity,
                    'location': SonarQubeScanParser._build_location(issue),
                    'description': issue.get('message') or issue.get('description', ''),
                    'remediation': SonarQubeScanParser._get_remediation_advice(rule_key, severity),
                    'rule_key': rule_key,
                    'component': issue.get('component'),
                    'line': issue.get('line'),
                    'effort': issue.get('effort'),
                    'debt': issue.get('debt'),
                    'type': issue.get('type', 'CODE_SMELL'),
                    'status': issue.get('status', 'OPEN')
                }
                findings.append(finding)
                
            return findings
            
        except Exception as e:
            print(f"Error parsing SonarQube JSON report: {e}")
            return []
    
    @staticmethod
    def parse_xml_report(filepath: str) -> List[Dict[str, Any]]:
        """Parse SonarQube XML report format"""
        try:
            tree = ET.parse(filepath)
            root = tree.getroot()
            findings = []
            
            # Handle different XML structures for SonarQube
            for issue in root.findall('.//issue') or root.findall('.//violation'):
                rule_key = issue.get('rule') or issue.get('ruleKey', '')
                severity = SonarQubeScanParser._normalize_severity(issue.get('severity'))
                
                finding = {
                    'source': 'SonarQube',
                    'title': issue.get('message') or rule_key,
                    'severity': severity,
                    'location': f"{issue.get('component', '')}:{issue.get('line', '')}",
                    'description': issue.get('message') or issue.text or '',
                    'remediation': SonarQubeScanParser._get_remediation_advice(rule_key, severity),
                    'rule_key': rule_key,
                    'component': issue.get('component'),
                    'line': issue.get('line'),
                    'type': issue.get('type', 'CODE_SMELL'),
                    'status': issue.get('status', 'OPEN')
                }
                findings.append(finding)
                
            return findings
            
        except Exception as e:
            print(f"Error parsing SonarQube XML report: {e}")
            return []
    
    @staticmethod
    def _normalize_severity(severity: str) -> str:
        """Normalize SonarQube severity levels"""
        if not severity:
            return 'Info'
        
        severity_map = {
            'BLOCKER': 'Critical',
            'CRITICAL': 'Critical', 
            'MAJOR': 'High',
            'MINOR': 'Medium',
            'INFO': 'Info'
        }
        
        return severity_map.get(severity.upper(), severity.title())
    
    @staticmethod
    def _build_location(issue: Dict) -> str:
        """Build location string from SonarQube issue data"""
        component = issue.get('component', '')
        line = issue.get('line', '')
        
        if component and line:
            return f"{component}:{line}"
        elif component:
            return component
        else:
            return 'Unknown location'
    
    @staticmethod
    def _get_remediation_advice(rule_key: str, severity: str) -> str:
        """Provide remediation advice based on SonarQube rule"""
        remediation_map = {
            'squid:S00108': 'Remove empty blocks or add meaningful code',
            'squid:S1192': 'Define string constants to avoid duplication',
            'squid:S1481': 'Remove unused local variables',
            'squid:S2259': 'Add null checks before using objects',
            'squid:S2068': 'Remove hardcoded credentials and use secure storage',
            'squid:S2070': 'Use cryptographically strong random number generators',
            'squid:S2076': 'Validate and sanitize user inputs to prevent injection',
        }
        
        specific_advice = remediation_map.get(rule_key, '')
        
        if specific_advice:
            return specific_advice
        
        # Generic advice based on severity
        if severity == 'Critical':
            return 'This issue requires immediate attention as it poses significant security or reliability risks'
        elif severity == 'High':
            return 'Address this issue soon as it may impact application security or maintainability'
        else:
            return 'Consider fixing this issue to improve code quality'


class NetsparkerScanParser:
    """Parser for Netsparker scan reports"""
    
    @staticmethod
    def parse_json_report(filepath: str) -> List[Dict[str, Any]]:
        """Parse Netsparker JSON report"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            findings = []
            vulnerabilities = data.get('Vulnerabilities', []) or data.get('vulnerabilities', [])
            
            for vuln in vulnerabilities:
                finding = {
                    'source': 'Netsparker',
                    'title': vuln.get('Name') or vuln.get('title'),
                    'severity': NetsparkerScanParser._normalize_severity(vuln.get('Severity')),
                    'location': vuln.get('Url') or vuln.get('url'),
                    'description': vuln.get('Description') or vuln.get('Impact'),
                    'remediation': vuln.get('RemedyReferences') or vuln.get('remediation'),
                    'cvss_score': vuln.get('CvssScore'),
                    'category': vuln.get('Type') or vuln.get('Classification'),
                    'certainty': vuln.get('Certainty'),
                    'state': vuln.get('State', 'Present'),
                    'confirmed': vuln.get('Confirmed', False)
                }
                findings.append(finding)
                
            return findings
            
        except Exception as e:
            print(f"Error parsing Netsparker JSON report: {e}")
            return []
    
    @staticmethod
    def parse_xml_report(filepath: str) -> List[Dict[str, Any]]:
        """Parse Netsparker XML report"""
        try:
            tree = ET.parse(filepath)
            root = tree.getroot()
            findings = []
            
            for vuln in root.findall('.//vulnerability') or root.findall('.//Vulnerability'):
                finding = {
                    'source': 'Netsparker',
                    'title': NetsparkerScanParser._get_xml_text(vuln, ['name', 'Name']),
                    'severity': NetsparkerScanParser._normalize_severity(
                        NetsparkerScanParser._get_xml_text(vuln, ['severity', 'Severity'])
                    ),
                    'location': NetsparkerScanParser._get_xml_text(vuln, ['url', 'Url']),
                    'description': NetsparkerScanParser._get_xml_text(vuln, ['description', 'Description']),
                    'remediation': NetsparkerScanParser._get_xml_text(vuln, ['remediation', 'RemedyReferences']),
                    'category': NetsparkerScanParser._get_xml_text(vuln, ['type', 'Type']),
                    'certainty': NetsparkerScanParser._get_xml_text(vuln, ['certainty', 'Certainty']),
                    'state': NetsparkerScanParser._get_xml_text(vuln, ['state', 'State']) or 'Present'
                }
                findings.append(finding)
                
            return findings
            
        except Exception as e:
            print(f"Error parsing Netsparker XML report: {e}")
            return []
    
    @staticmethod
    def _normalize_severity(severity: str) -> str:
        """Normalize Netsparker severity levels"""
        if not severity:
            return 'Unknown'
        
        severity_map = {
            'Critical': 'Critical',
            'High': 'High', 
            'Important': 'High',
            'Medium': 'Medium',
            'Low': 'Low',
            'Information': 'Info',
            'BestPractice': 'Info'
        }
        
        return severity_map.get(severity, severity)
    
    @staticmethod
    def _get_xml_text(element, tag_names: List[str]) -> Optional[str]:
        """Get text from XML element using multiple possible tag names"""
        for tag in tag_names:
            elem = element.find(tag)
            if elem is not None and elem.text:
                return elem.text.strip()
        return None


def process_scan_reports(sonarqube_file=None, qualys_file=None, netsparker_file=None, generic_file=None) -> Dict[str, List[Dict]]:
    """Process uploaded scan reports and return consolidated findings"""
    results = {
        'sonarqube_findings': [],
        'qualys_findings': [],
        'netsparker_findings': [],
        'generic_findings': [],
        'summary': {
            'total_findings': 0,
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0,
            'sast_findings': 0,
            'dast_findings': 0
        },
        'correlation_analysis': []
    }
    
    # Process SonarQube report (SAST)
    if sonarqube_file:
        if sonarqube_file.endswith('.json'):
            results['sonarqube_findings'] = SonarQubeScanParser.parse_json_report(sonarqube_file)
        elif sonarqube_file.endswith('.xml'):
            results['sonarqube_findings'] = SonarQubeScanParser.parse_xml_report(sonarqube_file)
    
    # Process Qualys report (DAST)
    if qualys_file:
        if qualys_file.endswith('.json'):
            results['qualys_findings'] = QualysScanParser.parse_json_report(qualys_file)
        elif qualys_file.endswith('.xml'):
            results['qualys_findings'] = QualysScanParser.parse_xml_report(qualys_file)
        elif qualys_file.endswith('.csv'):
            results['qualys_findings'] = QualysScanParser.parse_csv_report(qualys_file)
    
    # Process Netsparker report (DAST)
    if netsparker_file:
        if netsparker_file.endswith('.json'):
            results['netsparker_findings'] = NetsparkerScanParser.parse_json_report(netsparker_file)
        elif netsparker_file.endswith('.xml'):
            results['netsparker_findings'] = NetsparkerScanParser.parse_xml_report(netsparker_file)
    
    # Process generic scan report
    if generic_file:
        results['generic_findings'] = parse_generic_scan_report(generic_file)
    
    # Calculate summary statistics
    sast_findings = results['sonarqube_findings'] + results['generic_findings']
    dast_findings = results['qualys_findings'] + results['netsparker_findings']
    all_findings = sast_findings + dast_findings
    
    results['summary']['total_findings'] = len(all_findings)
    results['summary']['sast_findings'] = len(sast_findings)
    results['summary']['dast_findings'] = len(dast_findings)
    
    for finding in all_findings:
        severity = finding.get('severity', '').lower()
        if severity == 'critical':
            results['summary']['critical'] += 1
        elif severity == 'high':
            results['summary']['high'] += 1
        elif severity == 'medium':
            results['summary']['medium'] += 1
        elif severity == 'low':
            results['summary']['low'] += 1
        else:
            results['summary']['info'] += 1
    
    # Generate SAST/DAST correlation analysis
    if sast_findings and dast_findings:
        results['correlation_analysis'] = generate_advanced_correlation(sast_findings, dast_findings)
    
    return results


def parse_generic_scan_report(filepath: str) -> List[Dict[str, Any]]:
    """Parse generic security scan reports (best effort)"""
    try:
        findings = []
        
        if filepath.endswith('.json'):
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Try common JSON structures
            issues = (
                data.get('vulnerabilities', []) or 
                data.get('issues', []) or 
                data.get('findings', []) or
                data.get('results', []) or
                [data] if isinstance(data, dict) else []
            )
            
            for issue in issues:
                finding = {
                    'source': 'Generic Scanner',
                    'title': (
                        issue.get('title') or issue.get('name') or 
                        issue.get('message') or issue.get('description', 'Unknown Issue')
                    ),
                    'severity': normalize_generic_severity(issue.get('severity') or issue.get('level')),
                    'location': (
                        issue.get('location') or issue.get('file') or 
                        issue.get('url') or issue.get('component', 'Unknown')
                    ),
                    'description': issue.get('description') or issue.get('details', ''),
                    'remediation': issue.get('remediation') or issue.get('solution', ''),
                    'type': issue.get('type') or issue.get('category', 'Unknown'),
                    'confidence': issue.get('confidence') or issue.get('certainty'),
                    'cwe_id': issue.get('cwe') or issue.get('cwe_id'),
                    'cvss_score': issue.get('cvss') or issue.get('score')
                }
                findings.append(finding)
        
        elif filepath.endswith(('.xml', '.csv', '.txt')):
            # Basic parsing for other formats
            findings.append({
                'source': 'Generic Scanner',
                'title': f'Report uploaded: {os.path.basename(filepath)}',
                'severity': 'Info',
                'location': filepath,
                'description': 'Generic security scan report detected. Manual review recommended.',
                'remediation': 'Review the uploaded report for specific findings and recommendations.',
                'type': 'Report Upload'
            })
        
        return findings
        
    except Exception as e:
        print(f"Error parsing generic scan report: {e}")
        return [{
            'source': 'Generic Scanner',
            'title': 'Report Parse Error',
            'severity': 'Info', 
            'location': filepath,
            'description': f'Could not automatically parse report: {str(e)}',
            'remediation': 'Manually review the uploaded report file.',
            'type': 'Parse Error'
        }]


def normalize_generic_severity(severity: str) -> str:
    """Normalize severity from various scanner formats"""
    if not severity:
        return 'Info'
    
    severity = str(severity).upper()
    
    # Map various severity formats
    severity_mappings = {
        'CRITICAL': 'Critical', 'BLOCKER': 'Critical', 'FATAL': 'Critical',
        'HIGH': 'High', 'MAJOR': 'High', 'ERROR': 'High', 'IMPORTANT': 'High',
        'MEDIUM': 'Medium', 'MODERATE': 'Medium', 'WARNING': 'Medium', 'WARN': 'Medium',
        'LOW': 'Low', 'MINOR': 'Low', 'NOTE': 'Low',
        'INFO': 'Info', 'INFORMATIONAL': 'Info', 'INFORMATION': 'Info'
    }
    
    return severity_mappings.get(severity, severity.title())


def generate_advanced_correlation(sast_findings: List[Dict], dast_findings: List[Dict]) -> List[Dict]:
    """Generate advanced SAST/DAST correlation analysis"""
    correlations = []
    
    # Enhanced vulnerability mapping
    vulnerability_patterns = {
        'sql_injection': {
            'sast_patterns': ['sql', 'injection', 'query', 'statement', 'database'],
            'dast_patterns': ['sql injection', 'sqli', 'database', 'query injection'],
            'threat_category': 'Injection Attacks',
            'stride_mapping': 'Tampering, Information Disclosure'
        },
        'xss': {
            'sast_patterns': ['xss', 'cross-site', 'script', 'html', 'output encoding'],
            'dast_patterns': ['cross-site scripting', 'xss', 'script injection', 'html injection'],
            'threat_category': 'Client-Side Injection',
            'stride_mapping': 'Tampering, Elevation of Privilege'
        },
        'authentication': {
            'sast_patterns': ['authentication', 'login', 'password', 'credential', 'session'],
            'dast_patterns': ['authentication', 'login', 'session', 'credential', 'password'],
            'threat_category': 'Authentication Weaknesses',
            'stride_mapping': 'Spoofing, Elevation of Privilege'
        },
        'authorization': {
            'sast_patterns': ['authorization', 'access control', 'permission', 'privilege'],
            'dast_patterns': ['authorization', 'access control', 'privilege escalation', 'bypass'],
            'threat_category': 'Access Control Issues',
            'stride_mapping': 'Elevation of Privilege'
        },
        'crypto': {
            'sast_patterns': ['crypto', 'encryption', 'hash', 'certificate', 'tls', 'ssl'],
            'dast_patterns': ['ssl', 'tls', 'encryption', 'certificate', 'crypto'],
            'threat_category': 'Cryptographic Vulnerabilities',
            'stride_mapping': 'Information Disclosure, Tampering'
        },
        'input_validation': {
            'sast_patterns': ['validation', 'sanitization', 'input', 'parameter'],
            'dast_patterns': ['injection', 'parameter', 'input validation', 'bypass'],
            'threat_category': 'Input Validation Issues',
            'stride_mapping': 'Tampering, Information Disclosure'
        }
    }
    
    # Perform correlation analysis
    for vuln_type, patterns in vulnerability_patterns.items():
        sast_matches = []
        dast_matches = []
        
        # Find SAST matches
        for finding in sast_findings:
            title_desc = f"{finding.get('title', '')} {finding.get('description', '')}".lower()
            if any(pattern in title_desc for pattern in patterns['sast_patterns']):
                sast_matches.append(finding)
        
        # Find DAST matches  
        for finding in dast_findings:
            title_desc = f"{finding.get('title', '')} {finding.get('description', '')}".lower()
            if any(pattern in title_desc for pattern in patterns['dast_patterns']):
                dast_matches.append(finding)
        
        # Create correlation if both SAST and DAST findings exist
        if sast_matches and dast_matches:
            correlation = {
                'vulnerability_type': vuln_type.replace('_', ' ').title(),
                'threat_category': patterns['threat_category'],
                'stride_mapping': patterns['stride_mapping'],
                'sast_count': len(sast_matches),
                'dast_count': len(dast_matches),
                'risk_level': calculate_correlation_risk(sast_matches, dast_matches),
                'sast_locations': [f.get('location', 'Unknown') for f in sast_matches[:3]],
                'dast_locations': [f.get('location', 'Unknown') for f in dast_matches[:3]],
                'recommendation': generate_correlation_recommendation(vuln_type, sast_matches, dast_matches),
                'priority': 'High' if len(sast_matches) > 2 and len(dast_matches) > 1 else 'Medium'
            }
            correlations.append(correlation)
    
    return correlations


def calculate_correlation_risk(sast_findings: List[Dict], dast_findings: List[Dict]) -> str:
    """Calculate risk level based on SAST/DAST finding correlation"""
    sast_critical = sum(1 for f in sast_findings if f.get('severity', '').lower() in ['critical', 'high'])
    dast_critical = sum(1 for f in dast_findings if f.get('severity', '').lower() in ['critical', 'high'])
    
    if sast_critical > 0 and dast_critical > 0:
        return 'Critical'
    elif (sast_critical > 0 and len(dast_findings) > 0) or (dast_critical > 0 and len(sast_findings) > 0):
        return 'High'
    elif len(sast_findings) > 2 and len(dast_findings) > 2:
        return 'Medium'
    else:
        return 'Low'


def generate_correlation_recommendation(vuln_type: str, sast_findings: List[Dict], dast_findings: List[Dict]) -> str:
    """Generate specific recommendations based on correlated findings"""
    recommendations = {
        'sql_injection': f"Code review shows {len(sast_findings)} SQL-related issues while runtime testing found {len(dast_findings)} injection vulnerabilities. Implement parameterized queries and input validation.",
        'xss': f"Static analysis detected {len(sast_findings)} XSS-prone code patterns and dynamic testing confirmed {len(dast_findings)} exploitable instances. Apply output encoding and Content Security Policy.",
        'authentication': f"Authentication weaknesses found in both code ({len(sast_findings)} issues) and runtime ({len(dast_findings)} issues). Strengthen authentication mechanisms and session management.",
        'authorization': f"Access control issues present in code ({len(sast_findings)}) and exploitable via web interface ({len(dast_findings)}). Review and fix authorization logic.",
        'crypto': f"Cryptographic issues found in code ({len(sast_findings)}) with corresponding runtime vulnerabilities ({len(dast_findings)}). Update crypto implementations and certificate management.",
        'input_validation': f"Input validation gaps detected in static analysis ({len(sast_findings)}) and confirmed exploitable ({len(dast_findings)}). Implement comprehensive input sanitization."
    }
    
    return recommendations.get(vuln_type, f"Address {len(sast_findings)} code-level and {len(dast_findings)} runtime issues for this vulnerability category.")