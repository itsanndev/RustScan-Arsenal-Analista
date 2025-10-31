#!/usr/bin/env python3
"""
RustScan Web Analysis Pipeline
Análisis automatizado de servicios web descubiertos con RustScan
"""

import sys
import json
import requests
import subprocess
import concurrent.futures
from datetime import datetime
from urllib.parse import urljoin
import urllib3
import socket

# Deshabilitar warnings SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class WebAnalysisPipeline:
    def __init__(self, targets_file):
        self.targets_file = targets_file
        self.output_dir = f"web_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.results = {
            'pipeline': 'web-analysis',
            'timestamp': datetime.now().isoformat(),
            'targets_file': targets_file,
            'web_services': []
        }
        
        # Crear directorio de salida
        import os
        os.makedirs(self.output_dir, exist_ok=True)
    
    def discover_web_services(self):
        """Descubrir servicios web usando RustScan"""
        print("Discovering web services with RustScan...")
        
        # Escanear puertos web comunes
        cmd = f"rustscan -a - -p 80,443,8080,8443,3000,5000,8000,9000 --greppable < {self.targets_file}"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        web_services = []
        for line in result.stdout.split('\n'):
            if '/open/' in line:
                parts = line.split()
                if len(parts) >= 2:
                    ip = parts[0]
                    port = parts[1].split('/')[0]
                    protocol = 'https' if port in ['443', '8443'] else 'http'
                    url = f"{protocol}://{ip}:{port}"
                    web_services.append({
                        'ip': ip,
                        'port': port,
                        'protocol': protocol,
                        'url': url,
                        'discovered': datetime.now().isoformat()
                    })
        
        print(f"Discovered {len(web_services)} web services")
        return web_services
    
    def analyze_web_service(self, service):
        """Análisis completo de un servicio web"""
        print(f"Analyzing web service: {service['url']}")
        
        analysis = {
            'target': service['url'],
            'basic_info': {},
            'security_headers': {},
            'technologies': [],
            'vulnerability_indicators': [],
            'analysis_timestamp': datetime.now().isoformat()
        }
        
        try:
            # Prueba de conectividad básica
            response = requests.get(
                service['url'],
                timeout=10,
                verify=False,
                allow_redirects=True,
                headers={'User-Agent': 'RustScan-Web-Analyzer/1.0'}
            )
            
            # Información básica
            analysis['basic_info'] = {
                'status_code': response.status_code,
                'content_length': len(response.content),
                'final_url': response.url,
                'response_time_ms': response.elapsed.total_seconds() * 1000,
                'server_header': response.headers.get('Server', 'Not specified'),
                'content_type': response.headers.get('Content-Type', 'Not specified')
            }
            
            # Análisis de headers de seguridad
            analysis['security_headers'] = self.analyze_security_headers(response.headers)
            
            # Detección de tecnologías
            analysis['technologies'] = self.detect_technologies(response)
            
            # Indicadores de vulnerabilidad
            analysis['vulnerability_indicators'] = self.check_vulnerability_indicators(service, response)
            
            # Fingerprinting adicional
            analysis['fingerprinting'] = self.perform_fingerprinting(service)
            
        except requests.exceptions.RequestException as e:
            analysis['error'] = f"Request failed: {str(e)}"
        except Exception as e:
            analysis['error'] = f"Analysis error: {str(e)}"
        
        return analysis
    
    def analyze_security_headers(self, headers):
        """Analizar headers de seguridad"""
        security_checks = {}
        important_headers = [
            'Content-Security-Policy',
            'Strict-Transport-Security',
            'X-Content-Type-Options',
            'X-Frame-Options',
            'X-XSS-Protection',
            'Referrer-Policy'
        ]
        
        for header in important_headers:
            if header in headers:
                security_checks[header] = {
                    'present': True,
                    'value': headers[header],
                    'status': 'OK'
                }
            else:
                security_checks[header] = {
                    'present': False,
                    'status': 'MISSING'
                }
        
        return security_checks
    
    def detect_technologies(self, response):
        """Detección básica de tecnologías web"""
        technologies = []
        server_header = response.headers.get('Server', '').lower()
        content = response.text.lower()
        
        # Detección por Server header
        if 'apache' in server_header:
            technologies.append('Apache')
        elif 'nginx' in server_header:
            technologies.append('Nginx')
        elif 'iis' in server_header:
            technologies.append('IIS')
        
        # Detección por contenido
        if 'wp-content' in content:
            technologies.append('WordPress')
        if 'drupal' in content:
            technologies.append('Drupal')
        if 'joomla' in content:
            technologies.append('Joomla')
        
        # Detección por headers específicos
        if 'x-powered-by' in response.headers:
            powered_by = response.headers['x-powered-by'].lower()
            if 'php' in powered_by:
                technologies.append('PHP')
            if 'asp.net' in powered_by:
                technologies.append('ASP.NET')
        
        return list(set(technologies))
    
    def check_vulnerability_indicators(self, service, response):
        """Verificar indicadores de vulnerabilidad comunes"""
        indicators = []
        
        # Versiones de servidor obsoletas
        server_header = response.headers.get('Server', '')
        if any(version in server_header for version in ['Apache/2.2', 'nginx/1.4', 'IIS/6.0']):
            indicators.append({
                'type': 'obsolete_server_version',
                'severity': 'medium',
                'message': f"Potentially obsolete server version: {server_header}"
            })
        
        # Headers de seguridad faltantes
        if 'X-Frame-Options' not in response.headers:
            indicators.append({
                'type': 'missing_security_header',
                'severity': 'low',
                'message': 'X-Frame-Options header missing'
            })
        
        # Información de servidor expuesta
        if 'Server' in response.headers and len(response.headers['Server']) > 0:
            indicators.append({
                'type': 'server_info_disclosure',
                'severity': 'low',
                'message': f"Server information exposed: {response.headers['Server']}"
            })
        
        return indicators
    
    def perform_fingerprinting(self, service):
        """Fingerprinting adicional del servicio"""
        fingerprint = {}
        
        try:
            # DNS lookup
            ip = socket.gethostbyname(service['ip'])
            fingerprint['resolved_ip'] = ip
            
            # SSL check si es HTTPS
            if service['protocol'] == 'https':
                fingerprint['ssl_enabled'] = True
                
                # Verificación SSL básica
                import ssl
                context = ssl.create_default_context()
                with socket.create_connection((service['ip'], int(service['port'])), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=service['ip']) as ssock:
                        fingerprint['ssl_cipher'] = ssock.cipher()
                        fingerprint['ssl_version'] = ssock.version()
            
        except Exception as e:
            fingerprint['error'] = str(e)
        
        return fingerprint
    
    def run_comprehensive_analysis(self):
        """Ejecutar análisis completo"""
        print("Starting comprehensive web analysis...")
        
        # Descubrir servicios web
        web_services = self.discover_web_services()
        
        if not web_services:
            print("No web services found")
            return
        
        # Analizar servicios en paralelo
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            future_to_service = {
                executor.submit(self.analyze_web_service, service): service 
                for service in web_services
            }
            
            for future in concurrent.futures.as_completed(future_to_service):
                service = future_to_service[future]
                try:
                    analysis_result = future.result()
                    self.results['web_services'].append(analysis_result)
                    print(f"Completed analysis for: {service['url']}")
                except Exception as e:
                    print(f"Analysis failed for {service['url']}: {e}")
        
        # Generar reportes
        self.generate_reports()
    
    def generate_reports(self):
        """Generar reportes de análisis"""
        # Reporte JSON completo
        with open(f'{self.output_dir}/web_analysis_report.json', 'w') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)
        
        # Reporte ejecutivo
        self.generate_executive_report()
        
        # Reporte de seguridad
        self.generate_security_report()
        
        print(f"Reports generated in: {self.output_dir}")
    
    def generate_executive_report(self):
        """Generar reporte ejecutivo"""
        total_services = len(self.results['web_services'])
        successful_analyses = len([s for s in self.results['web_services'] if 'error' not in s])
        
        with open(f'{self.output_dir}/executive_summary.txt', 'w') as f:
            f.write("WEB ANALYSIS EXECUTIVE SUMMARY\n")
            f.write("==============================\n\n")
            f.write(f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Targets File: {self.targets_file}\n")
            f.write(f"Total Web Services: {total_services}\n")
            f.write(f"Successful Analyses: {successful_analyses}\n\n")
            
            f.write("SUMMARY BY TECHNOLOGY:\n")
            f.write("---------------------\n")
            
            # Contar tecnologías
            tech_count = {}
            for service in self.results['web_services']:
                if 'technologies' in service:
                    for tech in service['technologies']:
                        tech_count[tech] = tech_count.get(tech, 0) + 1
            
            for tech, count in tech_count.items():
                f.write(f"{tech}: {count}\n")
            
            f.write("\nSECURITY OVERVIEW:\n")
            f.write("-----------------\n")
            
            # Contar problemas de seguridad
            security_issues = {
                'missing_headers': 0,
                'obsolete_versions': 0,
                'info_disclosure': 0
            }
            
            for service in self.results['web_services']:
                if 'security_headers' in service:
                    headers = service['security_headers']
                    for header_info in headers.values():
                        if not header_info['present']:
                            security_issues['missing_headers'] += 1
                
                if 'vulnerability_indicators' in service:
                    for indicator in service['vulnerability_indicators']:
                        if 'obsolete' in indicator['type']:
                            security_issues['obsolete_versions'] += 1
                        if 'disclosure' in indicator['type']:
                            security_issues['info_disclosure'] += 1
            
            f.write(f"Missing Security Headers: {security_issues['missing_headers']}\n")
            f.write(f"Obsolete Versions: {security_issues['obsolete_versions']}\n")
            f.write(f"Information Disclosure: {security_issues['info_disclosure']}\n")
    
    def generate_security_report(self):
        """Generar reporte de seguridad detallado"""
        with open(f'{self.output_dir}/security_findings.txt', 'w') as f:
            f.write("SECURITY FINDINGS REPORT\n")
            f.write("=======================\n\n")
            
            for service in self.results['web_services']:
                f.write(f"SERVICE: {service.get('target', 'Unknown')}\n")
                f.write("-" * 50 + "\n")
                
                if 'error' in service:
                    f.write(f"ERROR: {service['error']}\n\n")
                    continue
                
                # Headers de seguridad
                f.write("SECURITY HEADERS:\n")
                if 'security_headers' in service:
                    for header, info in service['security_headers'].items():
                        status = "PRESENT" if info['present'] else "MISSING"
                        f.write(f"  {header}: {status}\n")
                
                # Indicadores de vulnerabilidad
                if 'vulnerability_indicators' in service and service['vulnerability_indicators']:
                    f.write("\nVULNERABILITY INDICATORS:\n")
                    for indicator in service['vulnerability_indicators']:
                        f.write(f"  [{indicator['severity'].upper()}] {indicator['message']}\n")
                
                f.write("\n")

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 web-analysis.py <targets_file>")
        print("Example: python3 web-analysis.py targets.txt")
        sys.exit(1)
    
    targets_file = sys.argv[1]
    
    pipeline = WebAnalysisPipeline(targets_file)
    pipeline.run_comprehensive_analysis()

if __name__ == "__main__":
    main()