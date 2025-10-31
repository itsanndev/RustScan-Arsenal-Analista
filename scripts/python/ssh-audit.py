#!/usr/bin/env python3
# metadata: tags = ["security", "ssh", "audit"]
# metadata: trigger_port = "22"
# metadata: developer = "security-team"
# metadata: call_format = "python3 {{script}} {{ip}} {{port}}"

"""
RustScan RSE - SSH Service Security Auditor
Auditoría de seguridad para servicios SSH con detección de configuraciones inseguras
"""

import sys
import socket
import paramiko
import json
import subprocess
from datetime import datetime

class SSHSecurityAuditor:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = int(port)
        self.results = {
            'scanner': 'ssh-security-auditor',
            'timestamp': datetime.now().isoformat(),
            'target': f"{ip}:{port}",
            'findings': []
        }
    
    def comprehensive_ssh_audit(self):
        """Auditoría completa de seguridad SSH"""
        print(f"INICIANDO AUDITORIA SSH {self.ip}:{self.port}")
        
        # Fase 1: Banner grabbing y fingerprinting
        banner_info = self.grab_ssh_banner()
        if banner_info:
            self.results['findings'].extend(banner_info)
        
        # Fase 2: Análisis de configuración (sin autenticación)
        config_findings = self.analyze_ssh_configuration()
        self.results['findings'].extend(config_findings)
        
        # Fase 3: Detección de vulnerabilidades conocidas
        vuln_findings = self.check_known_vulnerabilities()
        self.results['findings'].extend(vuln_findings)
    
    def grab_ssh_banner(self):
        """Obtener banner SSH y extraer información"""
        findings = []
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((self.ip, self.port))
            
            # Recibir banner del servidor
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            findings.append({
                'type': 'ssh_banner',
                'severity': 'info',
                'message': f"Banner SSH: {banner}",
                'data': {
                    'raw_banner': banner,
                    'protocol_version': self.extract_ssh_version(banner)
                }
            })
            
            # Análisis del banner
            banner_analysis = self.analyze_ssh_banner(banner)
            findings.extend(banner_analysis)
            
        except socket.timeout:
            findings.append({
                'type': 'connection_timeout',
                'severity': 'low',
                'message': "Timeout al conectar con el servicio SSH"
            })
        except Exception as e:
            findings.append({
                'type': 'banner_grab_error',
                'severity': 'low',
                'message': f"Error obteniendo banner: {str(e)}"
            })
        
        return findings
    
    def extract_ssh_version(self, banner):
        """Extraer versión SSH del banner"""
        if 'SSH-2.0' in banner:
            return 'SSH-2.0'
        elif 'SSH-1.99' in banner:
            return 'SSH-1.99 (compatibilidad con SSH-1)'
        elif 'SSH-1.5' in banner:
            return 'SSH-1.5 (obsoleto)'
        else:
            return 'Desconocido'
    
    def analyze_ssh_banner(self, banner):
        """Analizar banner SSH para detectar problemas de seguridad"""
        findings = []
        
        # Detectar SSH versión 1 (inseguro)
        if 'SSH-1.5' in banner or 'SSH-1.99' in banner:
            findings.append({
                'type': 'ssh_version_1_detected',
                'severity': 'high',
                'message': "SSH versión 1 detectado - VULNERABLE",
                'data': {
                    'issue': 'SSHv1 tiene vulnerabilidades conocidas',
                    'recommendation': 'Deshabilitar SSHv1 y usar exclusivamente SSHv2'
                }
            })
        
        # Detectar software y versiones específicas
        software_versions = {
            'OpenSSH_7.4': 'medium',  # Versiones antiguas pueden tener vulnerabilidades
            'OpenSSH_7.3': 'medium',
            'OpenSSH_7.2': 'medium',
            'OpenSSH_6.': 'high',     # Versiones muy antiguas
            'OpenSSH_5.': 'high',
            'Dropbear': 'info',
        }
        
        for software, severity in software_versions.items():
            if software in banner:
                findings.append({
                    'type': 'ssh_software_version',
                    'severity': severity,
                    'message': f"Software SSH detectado: {software}",
                    'data': {
                        'software': software,
                        'recommendation': 'Actualizar a versión más reciente si es necesario'
                    }
                })
        
        return findings
    
    def analyze_ssh_configuration(self):
        """Analizar configuración SSH (métodos no intrusivos)"""
        findings = []
        
        try:
            # Intentar conexión SSH para detectar métodos de autenticación
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Timeout corto para no bloquear
            client.connect(
                self.ip, 
                port=self.port, 
                username='invaliduser', 
                password='invalidpass',
                timeout=5,
                allow_agent=False,
                look_for_keys=False
            )
            
        except paramiko.AuthenticationException:
            # Esto es normal - el servidor responde pero rechaza credenciales
            findings.append({
                'type': 'ssh_service_responding',
                'severity': 'info',
                'message': "Servicio SSH respondiendo correctamente",
                'data': {
                    'status': 'active',
                    'authentication': 'required'
                }
            })
            
        except paramiko.BadAuthenticationType as e:
            # El servidor indica qué tipos de autenticación soporta
            auth_methods = str(e).split(';')[-1] if ';' in str(e) else str(e)
            findings.append({
                'type': 'ssh_auth_methods',
                'severity': 'info',
                'message': f"Métodos de autenticación soportados: {auth_methods}",
                'data': {
                    'supported_methods': auth_methods,
                    'recommendation': 'Revisar métodos habilitados para seguridad'
                }
            })
            
        except Exception as e:
            # Otros errores pueden proporcionar información
            error_msg = str(e)
            if 'Error reading SSH protocol banner' in error_msg:
                findings.append({
                    'type': 'ssh_banner_error',
                    'severity': 'low',
                    'message': "Posible problema de compatibilidad de protocolo"
                })
        
        finally:
            try:
                client.close()
            except:
                pass
        
        # Recomendaciones de seguridad genéricas
        security_recommendations = [
            {
                'type': 'ssh_security_recommendation',
                'severity': 'medium',
                'message': "Deshabilitar autenticación por password si es posible",
                'data': {
                    'recommendation': 'Usar autenticación por clave pública',
                    'benefit': 'Mayor seguridad contra ataques de fuerza bruta'
                }
            },
            {
                'type': 'ssh_security_recommendation', 
                'severity': 'medium',
                'message': "Limitar usuarios permitidos para conexión SSH",
                'data': {
                    'recommendation': 'Usar AllowUsers en sshd_config',
                    'benefit': 'Reduce superficie de ataque'
                }
            },
            {
                'type': 'ssh_security_recommendation',
                'severity': 'low', 
                'message': "Configurar MaxAuthTries para limitar intentos",
                'data': {
                    'recommendation': 'MaxAuthTries 3 en sshd_config',
                    'benefit': 'Protección contra fuerza bruta'
                }
            }
        ]
        
        findings.extend(security_recommendations)
        return findings
    
    def check_known_vulnerabilities(self):
        """Verificar vulnerabilidades SSH conocidas"""
        findings = []
        
        # Esta es una lista de comprobaciones básicas
        # En un entorno real, se integraría con bases de datos de vulnerabilidades
        
        common_vulnerabilities = [
            {
                'name': 'SSH Weak Algorithms',
                'check': 'Verificar que no se usen algoritmos débiles',
                'severity': 'medium'
            },
            {
                'name': 'SSH CBC Mode Ciphers',
                'check': 'Verificar que no se usen cifrados en modo CBC',
                'severity': 'medium' 
            },
            {
                'name': 'SSH Server Key Strength',
                'check': 'Verificar fortaleza de claves del servidor',
                'severity': 'low'
            }
        ]
        
        for vuln in common_vulnerabilities:
            findings.append({
                'type': 'ssh_vulnerability_check',
                'severity': vuln['severity'],
                'message': f"Revisar: {vuln['name']}",
                'data': {
                    'vulnerability': vuln['name'],
                    'check': vuln['check'],
                    'recommendation': 'Ejecutar escáner especializado para verificación detallada'
                }
            })
        
        return findings
    
    def generate_report(self):
        """Generar reporte de auditoría SSH"""
        print("\n" + "="*60)
        print(f"SSH SECURITY AUDIT REPORT - {self.ip}:{self.port}")
        print("="*60)
        
        # Estadísticas de hallazgos
        high_count = len([f for f in self.results['findings'] if f.get('severity') == 'high'])
        medium_count = len([f for f in self.results['findings'] if f.get('severity') == 'medium'])
        low_count = len([f for f in self.results['findings'] if f.get('severity') == 'low'])
        info_count = len([f for f in self.results['findings'] if f.get('severity') == 'info'])
        
        print(f"\nESTADÍSTICAS DE AUDITORÍA:")
        print(f"   (1) CRITICOS: {high_count} | (2) MEDIOS: {medium_count} | (1) BAJOS: {low_count} |(0) INFO: {info_count}")
        
        # Mostrar hallazgos más importantes
        critical_findings = [f for f in self.results['findings'] if f.get('severity') in ['high', 'medium']]
        
        if critical_findings:
            print(f"\nHALLAZGOS CRÍTICOS:")
            for finding in critical_findings:
                icon = '1' if finding.get('severity') == 'high' else '2'
                print(f"   {icon} {finding['message']}")
        
        # Recomendaciones generales
        print(f"\nRECOMENDACIONES DE SEGURIDAD SSH:")
        print("   • Usar exclusivamente SSH versión 2")
        print("   • Deshabilitar autenticación por password")
        print("   • Implementar autenticación de dos factores")
        print("   • Limitar acceso por IP con firewalls")
        print("   • Mantener el software actualizado")
        
        print("\n" + "="*60)

def main():
    if len(sys.argv) != 3:
        print("Usage: python3 ssh-audit.py <IP> <PORT>")
        sys.exit(1)
    
    ip, port = sys.argv[1], sys.argv[2]
    
    auditor = SSHSecurityAuditor(ip, port)
    auditor.comprehensive_ssh_audit()
    auditor.generate_report()
    
    # Guardar reporte detallado
    output_file = f"ssh_audit_{ip}_{port}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(output_file, 'w') as f:
        json.dump(auditor.results, f, indent=2, ensure_ascii=False)
    
    print(f"REPORTE GENERADO: {output_file}")

if __name__ == "__main__":
    main()