#!/usr/bin/env python3
# metadata: tags = ["http", "security", "web"]
# metadata: trigger_port = "80,443,8080,8443"
# metadata: developer = "security-team"
# metadata: call_format = "python3 {{script}} {{ip}} {{port}}"

"""
RustScan RSE - HTTP Service Scanner Avanzado
Analiza servicios web y detecta configuraciones inseguras automáticamente
"""

import sys
import requests
import json
import ssl
import socket
from urllib.parse import urljoin
from datetime import datetime
import urllib3

# Deshabilitar warnings SSL para output más limpio
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class AdvancedHTTPScanner:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.results = {
            'scanner': 'http-scanner-rse',
            'timestamp': datetime.now().isoformat(),
            'target': f"{ip}:{port}",
            'findings': []
        }
    
    def comprehensive_http_scan(self):
        """Escaneo completo del servicio HTTP/HTTPS"""
        protocols = ['https', 'http'] if self.port in ['443', '8443'] else ['http', 'https']
        
        for protocol in protocols:
            try:
                base_url = f"{protocol}://{self.ip}:{self.port}"
                print(f"🔍 Analizando {base_url}...")
                
                # Prueba de conectividad básica
                connectivity = self.test_connectivity(base_url)
                if connectivity['success']:
                    self.results['findings'].extend(connectivity['findings'])
                    
                    # Análisis de seguridad
                    self.results['findings'].extend(self.security_headers_audit(base_url))
                    self.results['findings'].extend(self.http_methods_test(base_url))
                    self.results['findings'].extend(self.information_disclosure_check(base_url))
                    
            except Exception as e:
                self.results['findings'].append({
                    'type': 'scan_error',
                    'severity': 'low',
                    'message': f"Error escaneando {protocol}: {str(e)}"
                })
    
    def test_connectivity(self, base_url):
        """Test de conectividad y obtención de información básica"""
        findings = []
        
        try:
            response = requests.get(
                base_url,
                timeout=10,
                verify=False,
                allow_redirects=True,
                headers={
                    'User-Agent': 'RustScan-Security-Scanner/1.0',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
                }
            )
            
            # Información básica del servidor
            findings.append({
                'type': 'server_info',
                'severity': 'info',
                'data': {
                    'status_code': response.status_code,
                    'content_length': len(response.content),
                    'final_url': response.url,
                    'response_time_ms': response.elapsed.total_seconds() * 1000,
                    'server_header': response.headers.get('Server', 'No especificado'),
                    'content_type': response.headers.get('Content-Type', 'No especificado')
                }
            })
            
            return {'success': True, 'findings': findings}
            
        except requests.exceptions.SSLError as e:
            findings.append({
                'type': 'ssl_configuration_issue',
                'severity': 'medium',
                'message': f"Problema de SSL/TLS: {str(e)}"
            })
            return {'success': False, 'findings': findings}
            
        except Exception as e:
            findings.append({
                'type': 'connection_error',
                'severity': 'low',
                'message': f"No se pudo conectar: {str(e)}"
            })
            return {'success': False, 'findings': findings}
    
    def security_headers_audit(self, base_url):
        """Auditoría de headers de seguridad"""
        findings = []
        security_headers = {
            'Content-Security-Policy': {'severity': 'high', 'description': 'Protección contra XSS'},
            'Strict-Transport-Security': {'severity': 'high', 'description': 'Fuerza HTTPS'},
            'X-Content-Type-Options': {'severity': 'medium', 'description': 'Previene MIME sniffing'},
            'X-Frame-Options': {'severity': 'medium', 'description': 'Protección contra clickjacking'},
            'X-XSS-Protection': {'severity': 'medium', 'description': 'Protección XSS navegador'},
            'Referrer-Policy': {'severity': 'low', 'description': 'Control de información de referrer'}
        }
        
        try:
            response = requests.head(base_url, timeout=5, verify=False)
            
            for header, info in security_headers.items():
                if header in response.headers:
                    findings.append({
                        'type': 'security_header_present',
                        'severity': 'info',
                        'message': f"{header}: {response.headers[header]}",
                        'data': {
                            'header': header,
                            'value': response.headers[header],
                            'description': info['description']
                        }
                    })
                else:
                    findings.append({
                        'type': 'security_header_missing',
                        'severity': info['severity'],
                        'message': f"Header de seguridad faltante: {header}",
                        'data': {
                            'header': header,
                            'description': info['description'],
                            'recommendation': f'Implementar header {header}'
                        }
                    })
                        
        except Exception as e:
            findings.append({
                'type': 'headers_scan_error',
                'severity': 'low',
                'message': f"Error en auditoría de headers: {str(e)}"
            })
        
        return findings
    
    def http_methods_test(self, base_url):
        """Test de métodos HTTP permitidos"""
        findings = []
        
        try:
            # Test OPTIONS para métodos permitidos
            response = requests.options(base_url, timeout=5, verify=False)
            allowed_methods = response.headers.get('Allow', '')
            
            if allowed_methods:
                dangerous_methods = ['PUT', 'DELETE', 'TRACE', 'CONNECT']
                found_dangerous = [method for method in dangerous_methods if method in allowed_methods]
                
                if found_dangerous:
                    findings.append({
                        'type': 'dangerous_http_methods',
                        'severity': 'medium',
                        'message': f"Métodos HTTP peligrosos permitidos: {', '.join(found_dangerous)}",
                        'data': {
                            'allowed_methods': allowed_methods,
                            'dangerous_methods': found_dangerous,
                            'recommendation': 'Deshabilitar métodos HTTP innecesarios'
                        }
                    })
            
        except Exception as e:
            # Silenciar errores de métodos no permitidos
            pass
        
        return findings
    
    def information_disclosure_check(self, base_url):
        """Verificación de divulgación de información"""
        findings = []
        
        try:
            response = requests.get(base_url, timeout=5, verify=False)
            
            # Verificar versiones de software en headers
            server_header = response.headers.get('Server', '')
            powered_by = response.headers.get('X-Powered-By', '')
            
            # Detectar versiones específicas que pueden revelar información
            sensitive_versions = [
                'Apache/2.2', 'Apache/2.4', 'nginx/1.4', 'nginx/1.6',
                'IIS/6.0', 'IIS/7.0', 'IIS/8.0', 'PHP/5.4', 'PHP/5.6'
            ]
            
            for version in sensitive_versions:
                if version in server_header or version in powered_by:
                    findings.append({
                        'type': 'information_disclosure',
                        'severity': 'low',
                        'message': f"Posible divulgación de versión: {version}",
                        'data': {
                            'source': 'Server Header' if version in server_header else 'X-Powered-By',
                            'version': version,
                            'recommendation': 'Ocultar versiones de software en headers'
                        }
                    })
            
        except Exception as e:
            findings.append({
                'type': 'info_disclosure_scan_error',
                'severity': 'low',
                'message': f"Error en verificación de información: {str(e)}"
            })
        
        return findings
    
    def generate_report(self):
        """Generar reporte final consolidado"""
        print("\n" + "="*70)
        print(f"HTTP SECURITY SCAN REPORT - {self.ip}:{self.port}")
        print("="*70)
        
        # Agrupar hallazgos por severidad
        high_severity = [f for f in self.results['findings'] if f.get('severity') == 'high']
        medium_severity = [f for f in self.results['findings'] if f.get('severity') == 'medium']
        low_severity = [f for f in self.results['findings'] if f.get('severity') == 'low']
        info_severity = [f for f in self.results['findings'] if f.get('severity') == 'info']
        
        # Mostrar resumen ejecutivo
        print(f"\nRESUMEN EJECUTIVO:")
        print(f"   CRITICO: {len(high_severity)} | MEDIO: {len(medium_severity)} | BAJO: {len(low_severity)} | INFO: {len(info_severity)}")
        
        # Mostrar hallazgos por categoría de severidad
        severity_icons = {'high': '1', 'medium': '2', 'low': '3', 'info': '0'}
        
        for severity, findings_list in [('high', high_severity), ('medium', medium_severity), 
                                       ('low', low_severity), ('info', info_severity)]:
            if findings_list:
                print(f"\n{severity_icons[severity]} {severity.upper()} SEVERITY FINDINGS:")
                for finding in findings_list[:5]:  # Mostrar máximo 5 por categoría
                    print(f"   • {finding['message']}")
        
        print("\n" + "="*70)

def main():
    if len(sys.argv) != 3:
        print("Usage: python3 http-scanner.py <IP> <PORT>")
        sys.exit(1)
    
    ip, port = sys.argv[1], sys.argv[2]
    
    print(f"REALIZANDO ESCANNER HTTP A: {ip}:{port}")
    
    scanner = AdvancedHTTPScanner(ip, port)
    scanner.comprehensive_http_scan()
    scanner.generate_report()
    
    # Guardar resultados detallados en JSON
    output_file = f"http_scan_{ip}_{port}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(output_file, 'w') as f:
        json.dump(scanner.results, f, indent=2, ensure_ascii=False)
    
    print(f"REPORTE GENERADO: {output_file}")

if __name__ == "__main__":
    main()