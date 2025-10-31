#!/usr/bin/env python3
# metadata: tags = ["automation", "complete", "security"]
# metadata: trigger_port = "1-65535"
# metadata: developer = "security-team"
# metadata: call_format = "python3 {{script}} {{ip}} {{port}}"

"""
RustScan RSE - COMPLETE AUTOMATION SCRIPT
Orquesta múltiples herramientas y análisis en un pipeline automatizado
"""

import sys
import json
import subprocess
import os
import concurrent.futures
from datetime import datetime
from pathlib import Path

class CompleteSecurityAutomation:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.output_dir = f"automation_{ip}_{port}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.results = {
            'automation': 'complete-security-automation',
            'target': f"{ip}:{port}",
            'timestamp': datetime.now().isoformat(),
            'modules': {},
            'summary': {}
        }
        
        # Crear directorio de output
        Path(self.output_dir).mkdir(exist_ok=True)
    
    def check_tool_availability(self):
        """Verificar disponibilidad de herramientas en el sistema"""
        tools = {
            'nmap': 'Escaneo de servicios avanzado',
            'curl': 'Pruebas HTTP/HTTPS',
            'openssl': 'Análisis SSL/TLS',
            'whatweb': 'Fingerprinting web',
            'nikto': 'Escaneo de vulnerabilidades web',
            'sslscan': 'Análisis de certificados SSL'
        }
        
        available_tools = {}
        for tool, description in tools.items():
            try:
                subprocess.run([tool, '--version'], capture_output=True, check=True)
                available_tools[tool] = {'available': True, 'description': description}
                print(f"{tool}: DISPONIBLE")
            except (subprocess.CalledProcessError, FileNotFoundError):
                available_tools[tool] = {'available': False, 'description': description}
                print(f"{tool}: No disponible")
        
        self.results['tools_available'] = available_tools
        return available_tools
    
    def run_network_analysis(self):
        """Análisis completo de red y servicios"""
        print("🔍 Ejecutando análisis de red...")
        
        network_results = {}
        
        # 1. Test de conectividad básica
        network_results['connectivity'] = self.test_connectivity()
        
        # 2. Análisis de servicios con Nmap (si está disponible)
        if self.results['tools_available'].get('nmap', {}).get('available'):
            network_results['nmap_scan'] = self.run_targeted_nmap_scan()
        
        # 3. Análisis SSL/TLS si es puerto seguro
        if str(self.port) in ['443', '8443', '993', '995']:
            network_results['ssl_analysis'] = self.analyze_ssl_configuration()
        
        self.results['modules']['network_analysis'] = network_results
        return network_results
    
    def test_connectivity(self):
        """Pruebas básicas de conectividad"""
        connectivity = {}
        
        # Ping test
        try:
            result = subprocess.run(
                f"ping -c 3 -W 2 {self.ip}",
                shell=True, capture_output=True, text=True
            )
            connectivity['ping'] = {
                'success': result.returncode == 0,
                'output': result.stdout.strip()[:500]  # Primeros 500 caracteres
            }
        except Exception as e:
            connectivity['ping'] = {'success': False, 'error': str(e)}
        
        # Port connectivity test
        try:
            sock = __import__('socket').socket()
            sock.settimeout(5)
            start_time = datetime.now()
            result = sock.connect_ex((self.ip, int(self.port)))
            response_time = (datetime.now() - start_time).total_seconds()
            sock.close()
            
            connectivity['port_check'] = {
                'success': result == 0,
                'response_time_seconds': response_time,
                'status': 'open' if result == 0 else 'closed/filtered'
            }
        except Exception as e:
            connectivity['port_check'] = {'success': False, 'error': str(e)}
        
        return connectivity
    
    def run_targeted_nmap_scan(self):
        """Escaneo Nmap específico para el puerto"""
        try:
            # Escaneo específico para el puerto detectado
            cmd = f"nmap -p {self.port} -sV -sC --script safe {self.ip} -oN {self.output_dir}/nmap_scan.txt"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            return {
                'command': cmd,
                'success': result.returncode == 0,
                'output_file': f"{self.output_dir}/nmap_scan.txt"
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def analyze_ssl_configuration(self):
        """Análisis de configuración SSL/TLS"""
        ssl_results = {}
        
        # Usar openssl para análisis básico
        try:
            cmd = f"openssl s_client -connect {self.ip}:{self.port} -servername {self.ip} < /dev/null 2>/dev/null | openssl x509 -text -noout"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                ssl_results['certificate_info'] = {
                    'success': True,
                    'output': result.stdout.strip()[:1000]  # Primeros 1000 caracteres
                }
            else:
                ssl_results['certificate_info'] = {'success': False, 'error': 'No se pudo obtener certificado'}
                
        except Exception as e:
            ssl_results['certificate_info'] = {'success': False, 'error': str(e)}
        
        # Si sslscan está disponible, análisis más detallado
        if self.results['tools_available'].get('sslscan', {}).get('available'):
            try:
                cmd = f"sslscan {self.ip}:{self.port} > {self.output_dir}/sslscan.txt 2>&1"
                subprocess.run(cmd, shell=True)
                ssl_results['sslscan'] = {
                    'success': True,
                    'output_file': f"{self.output_dir}/sslscan.txt"
                }
            except Exception as e:
                ssl_results['sslscan'] = {'success': False, 'error': str(e)}
        
        return ssl_results
    
    def run_service_specific_analysis(self):
        """Análisis específico según el tipo de servicio"""
        service_results = {}
        
        # Determinar tipo de servicio basado en puerto
        service_type = self.determine_service_type()
        self.results['detected_service_type'] = service_type
        
        print(f"Ejecutando análisis para servicio: {service_type}")
        
        if service_type == 'web':
            service_results['web_analysis'] = self.analyze_web_service()
        elif service_type == 'ssh':
            service_results['ssh_analysis'] = self.analyze_ssh_service()
        elif service_type == 'database':
            service_results['database_analysis'] = self.analyze_database_service()
        elif service_type == 'mail':
            service_results['mail_analysis'] = self.analyze_mail_service()
        else:
            service_results['generic_analysis'] = self.generic_service_analysis()
        
        self.results['modules']['service_analysis'] = service_results
        return service_results
    
    def determine_service_type(self):
        """Determinar tipo de servicio basado en puerto común"""
        port = int(self.port)
        
        service_map = {
            'web': [80, 443, 8080, 8443, 3000, 5000, 8000, 9000],
            'ssh': [22],
            'database': [1433, 1521, 3306, 5432, 27017, 6379],
            'mail': [25, 110, 143, 993, 995, 587],
            'dns': [53],
            'ftp': [21],
            'rdp': [3389],
            'smb': [139, 445]
        }
        
        for service_type, ports in service_map.items():
            if port in ports:
                return service_type
        
        return 'unknown'
    
    def analyze_web_service(self):
        """Análisis específico para servicios web"""
        web_results = {}
        
        # Fingerprinting con WhatWeb si está disponible
        if self.results['tools_available'].get('whatweb', {}).get('available'):
            try:
                protocol = 'https' if self.port in [443, 8443] else 'http'
                url = f"{protocol}://{self.ip}:{self.port}"
                cmd = f"whatweb --color=never {url} > {self.output_dir}/whatweb.txt 2>&1"
                subprocess.run(cmd, shell=True)
                web_results['whatweb'] = {'success': True, 'output_file': f"{self.output_dir}/whatweb.txt"}
            except Exception as e:
                web_results['whatweb'] = {'success': False, 'error': str(e)}
        
        # Análisis con Nikto si está disponible
        if self.results['tools_available'].get('nikto', {}).get('available'):
            try:
                cmd = f"nikto -h {self.ip} -p {self.port} -o {self.output_dir}/nikto.txt -Format txt"
                subprocess.run(cmd, shell=True, timeout=120)  # Timeout de 2 minutos
                web_results['nikto'] = {'success': True, 'output_file': f"{self.output_dir}/nikto.txt"}
            except Exception as e:
                web_results['nikto'] = {'success': False, 'error': str(e)}
        
        # Pruebas HTTP básicas con curl
        try:
            protocol = 'https' if self.port in [443, 8443] else 'http'
            url = f"{protocol}://{self.ip}:{self.port}"
            
            # Test de headers
            cmd = f"curl -I --connect-timeout 5 {url} 2>/dev/null"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            web_results['http_headers'] = {
                'success': result.returncode == 0,
                'headers': result.stdout.strip() if result.stdout else 'No response'
            }
            
        except Exception as e:
            web_results['http_headers'] = {'success': False, 'error': str(e)}
        
        return web_results
    
    def analyze_ssh_service(self):
        """Análisis específico para servicios SSH"""
        ssh_results = {}
        
        # Banner grabbing y análisis básico
        try:
            # Usar el script ssh-audit.py si está disponible
            ssh_audit_script = Path(__file__).parent / "ssh-audit.py"
            if ssh_audit_script.exists():
                cmd = f"python3 {ssh_audit_script} {self.ip} {self.port}"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                ssh_results['ssh_audit'] = {
                    'success': result.returncode == 0,
                    'output': result.stdout.strip()[:2000]  # Primeros 2000 caracteres
                }
        except Exception as e:
            ssh_results['ssh_audit'] = {'success': False, 'error': str(e)}
        
        return ssh_results
    
    def analyze_database_service(self):
        """Análisis para servicios de base de datos"""
        db_results = {}