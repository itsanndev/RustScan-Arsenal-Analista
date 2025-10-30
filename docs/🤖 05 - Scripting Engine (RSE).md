
## 🎯 Índice
1. Introducción a RSE
2. Configuración del Sistema
3. Scripts en Python
4. Scripts en Bash/Shell
5. Scripts en Perl
6. Scripts Binarios Personalizados
7. Gestión de Tags y Filtros
8. Ejemplos Avanzados
9. Best Practices
10. Troubleshooting
    

---

## 🤖 Introducción a RSE

### ¿Qué es el RustScan Scripting Engine?
RSE es un sistema de extensibilidad que permite ejecutar scripts personalizados después de que RustScan completa su escaneo. Soporta múltiples lenguajes y se integra perfectamente con el flujo de trabajo de escaneo.

### Arquitectura de RSE
CAMBIAR A IMAGEN!!!!
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   RUSTSCAN      │───▶│   SCRIPTING      │───▶│   SCRIPTS       │
│   ESCANEO       │    │     ENGINE       │    │   PERSONALIZADOS│
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   PUERTOS       │    │   CONFIGURACIÓN  │    │   PYTHON        │
│   ABIERTOS      │    │     TOML         │    │   BASH          │
└─────────────────┘    └──────────────────┘    └─────────────────┘

### Flujo de Ejecución
```
# 1. RustScan descubre puertos abiertos
rustscan -a 192.168.1.1

# 2. RSE ejecuta scripts basados en configuración
# 3. Los scripts reciben: IP, PUERTOS, METADATOS
# 4. Resultados se integran en el output

```
---

## ⚙️ Configuración del Sistema

### Archivo de Configuración Principal
```
# ~/.rustscan_scripts.toml
# Configuración global del RustScan Scripting Engine

[scripts]
# Tags para filtrar scripts (solo se ejecutan scripts con estos tags)
tags = ["http", "security", "scanning", "production"]

# Puertos que activan la ejecución de scripts
ports = ["80", "443", "8080", "8443", "22", "21", "25", "53"]

# Desarrolladores autorizados (futura feature)
developer = ["security-team", "devops"]

# Formato de llamada a scripts
call_format = "python3 {{script}} {{ip}} {{port}}"

# Timeout para scripts en segundos
script_timeout = 30

# Habilitar/deshabilitar RSE
enabled = true
```

### Configuración por Script
```
# Configuración para scripts específicos

[[custom_scripts]]
name = "http-scanner"
path = "~/.rustscan/scripts/http_scanner.py"
tags = ["http", "web", "security"]
trigger_ports = ["80", "443", "8080", "8443"]
enabled = true
priority = 1

[[custom_scripts]]
name = "ssh-audit"
path = "~/.rustscan/scripts/ssh_audit.sh"
tags = ["security", "ssh", "audit"]
trigger_ports = ["22"]
enabled = true
priority = 2

[[custom_scripts]]
name = "database-check"
path = "~/.rustscan/scripts/database_check.py"
tags = ["database", "security"]
trigger_ports = ["3306", "5432", "1433", "27017"]
enabled = true
priority = 3
```

### Variables de Entorno para RSE
```
# Configurar en el perfil de shell
export RUSTSCAN_SCRIPTS_ENABLED=true
export RUSTSCAN_SCRIPTS_DIR="$HOME/.rustscan/scripts"
export RUSTSCAN_SCRIPTS_TIMEOUT=30
export RUSTSCAN_SCRIPTS_CALL_FORMAT="python3 {{script}} {{ip}} {{port}}"
```

---

## 🐍 Scripts en Python

### Estructura Básica de Script Python

```
#!/usr/bin/env python3
# metadata: tags = ["http", "security", "web"]
# metadata: trigger_port = "80,443,8080,8443"
# metadata: developer = "security-team"
# metadata: call_format = "python3 {{script}} {{ip}} {{port}}"

"""
Script de escaneo HTTP para RustScan RSE
Analiza servicios web y detecta configuraciones inseguras
"""

import sys
import requests
import json
from urllib.parse import urljoin
import ssl
import socket
from datetime import datetime

class HTTPScanner:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.results = {
            'scanner': 'http-scanner',
            'timestamp': datetime.now().isoformat(),
            'target': f"{ip}:{port}",
            'findings': []
        }
    
    def scan_http_service(self):
        """Escaneo completo del servicio HTTP/HTTPS"""
        protocols = ['https', 'http'] if self.port == '443' else ['http', 'https']
        
        for protocol in protocols:
            try:
                base_url = f"{protocol}://{self.ip}:{self.port}"
                self.results['findings'].extend(self.test_http_endpoint(base_url))
                
            except Exception as e:
                self.results['findings'].append({
                    'type': 'error',
                    'protocol': protocol,
                    'message': str(e)
                })
    
    def test_http_endpoint(self, base_url):
        """Testear endpoint HTTP específico"""
        findings = []
        
        try:
            # Test de conexión básica
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
            
            # Análisis de respuesta
            findings.extend(self.analyze_response(response, base_url))
            
        except requests.exceptions.SSLError as e:
            findings.append({
                'type': 'ssl_issue',
                'severity': 'medium',
                'message': f"SSL Error: {e}"
            })
        except requests.exceptions.ConnectionError:
            findings.append({
                'type': 'connection_error',
                'severity': 'low',
                'message': f"No se pudo conectar a {base_url}"
            })
        except Exception as e:
            findings.append({
                'type': 'error',
                'severity': 'low',
                'message': f"Error inesperado: {e}"
            })
        
        return findings
    
    def analyze_response(self, response, base_url):
        """Analizar respuesta HTTP para hallazgos de seguridad"""
        findings = []
        
        # Información básica
        findings.append({
            'type': 'basic_info',
            'severity': 'info',
            'data': {
                'status_code': response.status_code,
                'content_length': len(response.content),
                'final_url': response.url,
                'response_time': response.elapsed.total_seconds()
            }
        })
        
        # Headers de seguridad
        security_headers = self.check_security_headers(response.headers)
        findings.extend(security_headers)
        
        # Tecnologías detectadas
        technologies = self.detect_technologies(response)
        if technologies:
            findings.append({
                'type': 'technologies',
                'severity': 'info',
                'data': {'technologies': technologies}
            })
        
        # Configuraciones inseguras
        insecure_configs = self.check_insecure_configs(response)
        findings.extend(insecure_configs)
        
        return findings
    
    def check_security_headers(self, headers):
        """Verificar headers de seguridad"""
        findings = []
        security_headers = {
            'Content-Security-Policy': 'high',
            'Strict-Transport-Security': 'high',
            'X-Content-Type-Options': 'medium',
            'X-Frame-Options': 'medium',
            'X-XSS-Protection': 'medium'
        }
        
        for header, severity in security_headers.items():
            if header in headers:
                findings.append({
                    'type': 'security_header_present',
                    'severity': 'info',
                    'data': {
                        'header': header,
                        'value': headers[header]
                    }
                })
            else:
                findings.append({
                    'type': 'security_header_missing',
                    'severity': severity,
                    'data': {'header': header}
                })
        
        return findings
    
    def detect_technologies(self, response):
        """Detectar tecnologías web"""
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
        
        return list(set(technologies))
    
    def check_insecure_configs(self, response):
        """Buscar configuraciones inseguras"""
        findings = []
        
        # Server header que revela demasiada información
        server = response.headers.get('Server', '')
        if any(version in server for version in ['Apache/2.2', 'nginx/1.4', 'IIS/6.0']):
            findings.append({
                'type': 'outdated_server',
                'severity': 'medium',
                'message': f"Servidor potencialmente obsoleto: {server}"
            })
        
        # HTTP methods peligrosos
        try:
            options_resp = requests.options(response.url, timeout=5, verify=False)
            if 'PUT' in options_resp.headers.get('Allow', '') or 'DELETE' in options_resp.headers.get('Allow', ''):
                findings.append({
                    'type': 'dangerous_methods',
                    'severity': 'low',
                    'message': f"Métodos HTTP peligrosos permitidos: {options_resp.headers.get('Allow', '')}"
                })
        except:
            pass
        
        return findings
    
    def generate_report(self):
        """GENERAR REPORTE FINALl"""
        print("\n" + "="*60)
        print(f"HTTP SCAN REPORT - {self.ip}:{self.port}")
        print("="*60)
        
        for finding in self.results['findings']:
            severity_prior_indicator = {
                'high': '🔴',
                'medium': '🟡', 
                'low': '🟢',
                'info': '🔵'
            }.get(finding.get('severity', 'info'), '⚪')
            
            print(f"{severity_icon} {finding['type'].upper()}: {finding.get('message', '')}")
            if 'data' in finding:
                for key, value in finding['data'].items():
                    print(f"   {key}: {value}")
        
        print("="*60)

def main():
    if len(sys.argv) != 3:
        print("Usage: python3 http_scanner.py <IP> <PORT>")
        sys.exit(1)
    
    ip, port = sys.argv[1], sys.argv[2]
    
    # Deshabilitar warnings SSL para cleaner output
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    scanner = HTTPScanner(ip, port)
    scanner.scan_http_service()
    scanner.generate_report()
    
    # Guardar resultados detallados
    output_file = f"http_scan_{ip}_{port}.json"
    with open(output_file, 'w') as f:
        json.dump(scanner.results, f, indent=2)
    
    print(f"REPORTE GENERADO: {output_file}")

if __name__ == "__main__":
    main()
```

### Script Avanzado de Análisis SSH
```
#!/usr/bin/env python3
# metadata: tags = ["security", "ssh", "audit"]
# metadata: trigger_port = "22"
# metadata: call_format = "python3 {{script}} {{ip}} {{port}}"

import sys
import socket
import paramiko
import json
from datetime import datetime

class SSHAudit:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.results = {
            'scanner': 'ssh-audit',
            'timestamp': datetime.now().isoformat(),
            'target': f"{ip}:{port}",
            'findings': []
        }
    
    def audit_ssh_service(self):
        """Auditoría completa del servicio SSH"""
        try:
            # Conexión básica para banner grabbing
            self.grab_banner()
            
            # Análisis de configuración (si las credenciales están disponibles)
            self.analyze_ssh_config()
            
        except Exception as e:
            self.results['findings'].append({
                'type': 'error',
                'severity': 'low',
                'message': f"Error durante auditoría SSH: {e}"
            })
    
    def grab_banner(self):
        """Obtener banner SSH"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((self.ip, int(self.port)))
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            
            self.results['findings'].append({
                'type': 'ssh_banner',
                'severity': 'info',
                'data': {'banner': banner.strip()}
            })
            
        except Exception as e:
            self.results['findings'].append({
                'type': 'banner_grab_error',
                'severity': 'low',
                'message': f"No se pudo obtener banner: {e}"
            })
    
    def analyze_ssh_config(self):
        """Analizar configuración SSH (ejemplo básico)"""
        # Este es un ejemplo simplificado
        # En producción, usaría paramiko para análisis más detallado
        
        findings = [
            {
                'type': 'ssh_analysis',
                'severity': 'info',
                'message': "Análisis SSH completado (ejemplo)",
                'data': {
                    'recommendations': [
                        "Deshabilitar SSHv1",
                        "Usar clave pública en lugar de password",
                        "Limitar usuarios permitidos",
                        "Configurar MaxAuthTries=3"
                    ]
                }
            }
        ]
        
        self.results['findings'].extend(findings)

def main():
    if len(sys.argv) != 3:
        print("Usage: python3 ssh_audit.py <IP> <PORT>")
        sys.exit(1)
    
    ip, port = sys.argv[1], sys.argv[2]
    auditor = SSHAudit(ip, port)
    auditor.audit_ssh_service()
    
    # Mostrar resultados
    print(f"\n🔐 SSH AUDIT REPORT - {ip}:{port}")
    for finding in auditor.results['findings']:
        print(f"• {finding['type']}: {finding.get('message', '')}")

if __name__ == "__main__":
    main()
```

---
## 🐚 Scripts en Bash/Shell

### Script Básico de Detección de Servicios
```
#!/bin/bash
# metadata: tags = ["discovery", "basic"]
# metadata: trigger_port = "21,22,23,25,53,80,110,443,993,995"
# metadata: call_format = "bash {{script}} {{ip}} {{port}}"

#
# Script básico de detección de servicios para RustScan RSE
# Identifica servicios comunes y genera reporte simple
#

IP="$1"
PORT="$2"
TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")

echo "========================================="
echo "SERVICE DETECTION REPORT"
echo "Target: $IP:$PORT"
echo "Time: $TIMESTAMP"
echo "========================================="

# Detección basada en puerto
case $PORT in
    21)
        echo "Service: FTP"
        echo "Check: Anonymous login, version detection"
        ;;
    22)
        echo "Service: SSH"
        echo "Check: Banner grabbing, protocol version"
        ;;
    23)
        echo "Service: Telnet"
        echo "WARNING: Telnet is insecure"
        ;;
    25)
        echo "Service: SMTP"
        echo "CHECK: Open relay, banner"
        ;;
    53)
        echo "Service: DNS"
        echo "CHECK: Zone transfer, version"
        ;;
    80)
        echo "Service: HTTP"
        echo "CHECK: Web server, technologies"
        ;;
    443)
        echo "Service: HTTPS"
        echo "Check: SSL/TLS, web server"
        ;;
    110)
        echo "Service: POP3"
        echo "CHECK: Authentication methods"
        ;;
    993)
        echo "Service: IMAPS"
        echo "Check: SSL configuration"
        ;;
    995)
        echo "Service: POP3S"
        echo "CHECK: SSL configuration"
        ;;
    *)
        echo "Service: Unknown (Port $PORT)"
        echo "CHECK: Manual investigation required"
        ;;
esac

echo "========================================="
```

### Script Avanzado de Análisis de Red

```
#!/bin/bash
# metadata: tags = ["network", "advanced", "security"]
# metadata: trigger_port = "1-65535"
# metadata: call_format = "bash {{script}} {{ip}} {{port}}"

#
# Script avanzado de análisis de red
# Realiza múltiples checks de seguridad y red
#

IP="$1"
PORT="$2"
OUTPUT_DIR="/tmp/rustscan_analysis"
mkdir -p "$OUTPUT_DIR"

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" | tee -a "$OUTPUT_DIR/network_analysis.log"
}

log "Iniciando análisis de red para $IP:$PORT"

# 1. Test de conectividad básica
log "Realizando test de conectividad..."
ping -c 3 -W 2 "$IP" > "$OUTPUT_DIR/ping_test.txt" 2>&1
if [ $? -eq 0 ]; then
    log "Host SI RESPONDE a ping"
else
    log "Host NO responde a ping"
fi

# 2. DNS lookup inverso
log "Realizando DNS lookup..."
nslookup "$IP" > "$OUTPUT_DIR/dns_lookup.txt" 2>&1

# 3. Traceroute (si está disponible)
if command -v traceroute &> /dev/null; then
    log "Realizando traceroute..."
    traceroute -m 15 "$IP" > "$OUTPUT_DIR/traceroute.txt" 2>&1 &
fi

# 4. Análisis de servicios específicos
analyze_service() {
    local port=$1
    local ip=$2
    
    case $port in
        80|443|8080|8443)
            log "Detectado servicio web en puerto $port"
            # Test HTTP básico
            if command -v curl &> /dev/null; then
                curl -I --connect-timeout 5 "http://$ip:$port" > "$OUTPUT_DIR/http_$port.txt" 2>&1
            fi
            ;;
        22)
            log "Detectado SSH en puerto $port"
            # Banner grabbing SSH
            if command -v nc &> /dev/null; then
                echo "SSH-2.0-RustScan" | nc -w 3 "$ip" "$port" > "$OUTPUT_DIR/ssh_banner.txt" 2>&1
            fi
            ;;
        21)
            log "Detectado FTP en puerto $port"
            # Test FTP anónimo
            if command -v ftp &> /dev/null; then
                echo "quit" | ftp -n "$ip" "$port" > "$OUTPUT_DIR/ftp_test.txt" 2>&1
            fi
            ;;
    esac
}

analyze_service "$PORT" "$IP"

# 5. Resumen del análisis
log "Generando resumen del análisis..."
{
    echo "NETWORK ANALYSIS SUMMARY"
    echo "========================"
    echo "Target: $IP:$PORT"
    echo "Timestamp: $(date)"
    echo ""
    echo "CONNECTIVITY:"
    grep -E "GENERATED" "$OUTPUT_DIR/network_analysis.log" | tail -5
    echo ""
    echo "FILES GENERATED:"
    ls -la "$OUTPUT_DIR"/*.txt | awk '{print $9}'
} > "$OUTPUT_DIR/analysis_summary.txt"

log "ANALISIS COMPLETADO: $OUTPUT_DIR"

```
---

## 🐪 Scripts en Perl

### Script de Análisis de Servicios en Perl
```
#!/usr/bin/perl
# metadata: tags = ["perl", "analysis", "legacy"]
# metadata: trigger_port = "21,22,23,25,53,80,110,143,443,993,995"
# metadata: call_format = "perl {{script}} {{ip}} {{port}}"

#
# Script de análisis de servicios en Perl para RustScan RSE
# Compatible con sistemas legacy y proporciona análisis básico
#

use strict;
use warnings;
use Socket;
use Time::HiRes qw(gettimeofday tv_interval);

my ($ip, $port) = @ARGV;

unless ($ip && $port) {
    die "Usage: perl service_analyzer.pl <IP> <PORT>\n";
}

print "=" x 50 . "\n";
print "PERL SERVICE ANALYZER\n";
print "Target: $ip:$port\n";
print "Time: " . localtime() . "\n";
print "=" x 50 . "\n";

# Análisis de servicio basado en puerto
my $service_info = analyze_service($port);
print "Service: $service_info->{name}\n";
print "Description: $service_info->{description}\n";
print "Common Checks:\n";

foreach my $check (@{$service_info->{checks}}) {
    print "  - $check\n";
}

# Test de conectividad básico
my $connect_result = test_connectivity($ip, $port);
print "Connectivity: $connect_result->{status}\n";
if ($connect_result->{response_time}) {
    printf "Response Time: %.2f seconds\n", $connect_result->{response_time};
}

print "=" x 50 . "\n";

sub analyze_service {
    my $port = shift;
    
    my %services = (
        21 => {
            name => 'FTP',
            description => 'File Transfer Protocol',
            checks => ['Anonymous login', 'Version detection', 'Banner analysis']
        },
        22 => {
            name => 'SSH',
            description => 'Secure Shell',
            checks => ['Protocol version', 'Key exchange', 'Banner analysis']
        },
        23 => {
            name => 'Telnet',
            description => 'Teletype Network (INSECURE)',
            checks => ['Authentication', 'Banner analysis', 'Protocol version']
        },
        25 => {
            name => 'SMTP',
            description => 'Simple Mail Transfer Protocol',
            checks => ['Open relay', 'Banner analysis', 'Commands available']
        },
        53 => {
            name => 'DNS',
            description => 'Domain Name System',
            checks => ['Zone transfer', 'Version detection', 'Recursion']
        },
        80 => {
            name => 'HTTP',
            description => 'Hypertext Transfer Protocol',
            checks => ['Server version', 'HTTP methods', 'Security headers']
        },
        443 => {
            name => 'HTTPS',
            description => 'HTTP Secure',
            checks => ['SSL/TLS configuration', 'Certificate info', 'Security headers']
        }
    );
    
    return $services{$port} || {
        name => "Unknown (Port $port)",
        description => 'Service not in common list',
        checks => ['Manual investigation required']
    };
}

sub test_connectivity {
    my ($ip, $port) = @_;
    
    my $start_time = [gettimeofday];
    
    my $proto = getprotobyname('tcp');
    socket(my $sock, PF_INET, SOCK_STREAM, $proto) or return {
        status => 'Failed to create socket',
        response_time => undef
    };
    
    my $iaddr = inet_aton($ip) or return {
        status => 'Invalid IP address',
        response_time => undef
    };
    
    my $paddr = sockaddr_in($port, $iaddr);
    
    # Set timeout
    my $timeout = 5;
    eval {
        local $SIG{ALRM} = sub { die "timeout\n" };
        alarm $timeout;
        connect($sock, $paddr);
        alarm 0;
    };
    
    my $response_time = tv_interval($start_time);
    
    if ($@) {
        close $sock;
        return {
            status => 'Connection timeout or failed',
            response_time => $response_time
        };
    }
    
    close $sock;
    return {
        status => 'Connected successfully',
        response_time => $response_time
    };
}

1;
```

---

## 🔧 Scripts Binarios Personalizados

### Ejemplo: Integración con Herramientas Externas

bash

```
#!/bin/bash
# metadata: tags = ["external", "vulnerability"]
# metadata: trigger_port = "80,443,8080,8443"
# metadata: call_format = "bash {{script}} {{ip}} {{port}}"

#
# Script de integración con herramientas externas
# Ejemplo: Nuclei, WhatWeb, GoBuster
#

IP="$1"
PORT="$2"
PROTOCOL="http"

# Determinar protocolo
if [ "$PORT" = "443" ] || [ "$PORT" = "8443" ]; then
    PROTOCOL="https"
fi

TARGET_URL="$PROTOCOL://$IP:$PORT"
OUTPUT_DIR="/tmp/rustscan_external_$(date +%s)"
mkdir -p "$OUTPUT_DIR"

echo "🔗 Integrando herramientas externas para: $TARGET_URL"

# 1. WhatWeb para fingerprinting
if command -v whatweb &> /dev/null; then
    echo "Ejecutando WhatWeb..."
    whatweb --color=never "$TARGET_URL" > "$OUTPUT_DIR/whatweb.txt" 2>&1
    echo "WhatWeb completado"
fi

# 2. Nuclei para vulnerabilidades (si está configurado)
if command -v nuclei &> /dev/null && [ -d "$HOME/nuclei-templates" ]; then
    echo "Ejecutando Nuclei (scan rápido)..."
    nuclei -u "$TARGET_URL" -t "$HOME/nuclei-templates/http/exposures/" \
        -o "$OUTPUT_DIR/nuclei_exposures.txt" -silent 2>/dev/null &
fi

# 3. Test básico de directorios (si GoBuster está disponible)
if command -v gobuster &> /dev/null && [ -f "/usr/share/wordlists/dirb/common.txt" ]; then
    echo "Ejecutando GoBuster (scan rápido)..."
    gobuster dir -u "$TARGET_URL" -w "/usr/share/wordlists/dirb/common.txt" \
        -t 10 -o "$OUTPUT_DIR/gobuster_quick.txt" 2>/dev/null &
fi

# Esperar a que terminen los procesos en background
wait

# Generar reporte consolidado
echo "GENERANDO REPORTE DE INTEGRACIÓN"
{
    echo "EXTERNAL TOOLS INTEGRATION REPORT"
    echo "================================="
    echo "Target: $TARGET_URL"
    echo "Timestamp: $(date)"
    echo ""
    
    if [ -f "$OUTPUT_DIR/whatweb.txt" ]; then
        echo "WHATWEB RESULTS:"
        cat "$OUTPUT_DIR/whatweb.txt"
        echo ""
    fi
    
    if [ -f "$OUTPUT_DIR/nuclei_exposures.txt" ]; then
        echo "NUCLEI FINDINGS:"
        cat "$OUTPUT_DIR/nuclei_exposures.txt"
        echo ""
    fi
    
    if [ -f "$OUTPUT_DIR/gobuster_quick.txt" ]; then
        echo "GOBUSTER RESULTS:"
        head -20 "$OUTPUT_DIR/gobuster_quick.txt"
        echo ""
    fi
} > "$OUTPUT_DIR/external_tools_report.txt"

echo "✅ Integración completada. Reporte en: $OUTPUT_DIR/external_tools_report.txt"
```

---

## 🏷️ Gestión de Tags y Filtros

### Sistema de Tags Avanzado
```
# ~/.rustscan_scripts.toml
# Configuración avanzada de tags y filtros

[scripts]
# Tags globales que deben coincidir
tags = ["production", "security", "approved"]

# Tags que excluyen scripts
exclude_tags = ["experimental", "deprecated"]

# Tags requeridos para ejecución
require_tags = ["security"]

# Tags opcionales (bonus)
optional_tags = ["performance", "compliance"]

# Configuración de filtrado por entorno
[environment]
production = ["production", "stable"]
staging = ["staging", "testing"]
development = ["dev", "experimental"]

# Grupos de scripts
[script_groups]
web_scanning = ["http", "https", "web"]
network_scanning = ["tcp", "udp", "network"]
security_audit = ["security", "audit", "vulnerability"]

### Ejemplos de Uso de Tags

bash

# Ejecutar solo scripts con tag "http"
rustscan -a 192.168.1.1 --scripts "http"

# Ejecutar scripts con múltiples tags
rustscan -a 192.168.1.1 --scripts "http,security"

# Excluir scripts experimentales
rustscan -a 192.168.1.1 --scripts "all" --exclude-tags "experimental"

# Combinación compleja de filtros
rustscan -a 192.168.1.1 --scripts "security,production" --require-tags "approved"
```

---

## 🚀 Ejemplos Avanzados

### Script de Automatización Completa

```
#!/usr/bin/env python3
# metadata: tags = ["automation", "complete", "production"]
# metadata: trigger_port = "1-65535"
# metadata: call_format = "python3 {{script}} {{ip}} {{port}}"

import sys
import json
import subprocess
import os
from datetime import datetime
import concurrent.futures

class CompleteAutomation:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.results = {
            'automation': 'complete-scanner',
            'target': f"{ip}:{port}",
            'timestamp': datetime.now().isoformat(),
            'modules': {}
        }
    
    def run_all_checks(self):
        """Ejecutar todos los checks disponibles"""
        modules = {
            'network': self.network_checks,
            'service': self.service_checks,
            'security': self.security_checks,
            'performance': self.performance_checks
        }
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            future_to_module = {
                executor.submit(func): name 
                for name, func in modules.items()
            }
            
            for future in concurrent.futures.as_completed(future_to_module):
                module_name = future_to_module[future]
                try:
                    self.results['modules'][module_name] = future.result()
                except Exception as e:
                    self.results['modules'][module_name] = {'error': str(e)}
    
    def network_checks(self):
        """Checks de red"""
        checks = {}
        
        # Test de conectividad
        try:
            result = subprocess.run(
                f"ping -c 3 -W 2 {self.ip}",
                shell=True, capture_output=True, text=True
            )
            checks['ping'] = 'success' if result.returncode == 0 else 'failed'
        except:
            checks['ping'] = 'error'
        
        # Traceroute si está disponible
        try:
            result = subprocess.run(
                f"traceroute -m 10 {self.ip}",
                shell=True, capture_output=True, text=True, timeout=30
            )
            checks['traceroute'] = result.stdout[:500]  # Primeros 500 chars
        except:
            checks['traceroute'] = 'not_available'
        
        return checks
    
    def service_checks(self):
        """Checks de servicio específicos"""
        checks = {}
        
        # Detección de servicio basado en puerto
        service_map = {
            80: 'http', 443: 'https', 22: 'ssh', 21: 'ftp',
            25: 'smtp', 53: 'dns', 3389: 'rdp', 1433: 'mssql'
        }
        
        service = service_map.get(int(self.port), 'unknown')
        checks['detected_service'] = service
        
        # Check específico por servicio
        if service in ['http', 'https']:
            checks.update(self.http_checks())
        elif service == 'ssh':
            checks.update(self.ssh_checks())
        
        return checks
    
    def http_checks(self):
        """Checks específicos para HTTP/HTTPS"""
        checks = {}
        protocol = 'https' if self.port == '443' else 'http'
        url = f"{protocol}://{self.ip}:{self.port}"
        
        try:
            # Test básico con curl
            result = subprocess.run(
                f"curl -I --connect-timeout 5 {url}",
                shell=True, capture_output=True, text=True
            )
            checks['http_response'] = result.stdout
        except:
            checks['http_response'] = 'error'
        
        return checks
    
    def ssh_checks(self):
        """Checks específicos para SSH"""
        checks = {}
        
        try:
            # Banner grabbing
            result = subprocess.run(
                f"echo 'SSH-2.0-RustScan' | nc -w 3 {self.ip} {self.port}",
                shell=True, capture_output=True, text=True
            )
            checks['ssh_banner'] = result.stdout.strip()
        except:
            checks['ssh_banner'] = 'error'
        
        return checks
    
    def security_checks(self):
        """Checks de seguridad básicos"""
        checks = {}
        
        # Puertos conocidos por problemas de seguridad
        risky_ports = [23, 135, 139, 445, 1433, 3389]
        checks['is_risky_port'] = int(self.port) in risky_ports
        
        # Servicios con autenticación débil por defecto
        weak_auth_ports = [21, 23, 161, 162]
        checks['weak_auth_service'] = int(self.port) in weak_auth_ports
        
        return checks
    
    def performance_checks(self):
        """Checks de performance"""
        checks = {}
        
        try:
            # Test de respuesta
            import time
            start_time = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((self.ip, int(self.port)))
            response_time = time.time() - start_time
            sock.close()
            
            checks['response_time'] = f"{response_time:.3f}s"
            checks['connection_status'] = 'success' if result == 0 else 'failed'
        except:
            checks['response_time'] = 'error'
            checks['connection_status'] = 'error'
        
        return checks

def main():
    if len(sys.argv) != 3:
        print("Usage: python3 complete_automation.py <IP> <PORT>")
        sys.exit(1)
    
    ip, port = sys.argv[1], sys.argv[2]
    automation = CompleteAutomation(ip, port)
    automation.run_all_checks()
    
    # Mostrar resultados
    print(f"\n🤖 COMPLETE AUTOMATION REPORT - {ip}:{port}")
    for module, results in automation.results['modules'].items():
        print(f"\n{module.upper()} CHECKS:")
        for check, result in results.items():
            print(f"  {check}: {result}")
    
    # Guardar resultados completos
    output_file = f"automation_{ip}_{port}.json"
    with open(output_file, 'w') as f:
        json.dump(automation.results, f, indent=2)
    
    print(f"\nREPORTE COMPLETADO: {output_file}")

if __name__ == "__main__":
    main()

```
---

## ✅ Best Practices

### Estructura de Directorios Recomendada

```
~/.rustscan/
├── scripts/
│   ├── python/
│   │   ├── http_scanner.py
│   │   ├── ssh_audit.py
│   │   └── database_check.py
│   ├── bash/
│   │   └──  service_detector.sh
│   │   └── network_analyzer.sh
│   └── perl/
│       └── legacy_analyzer.pl
├── config/
│   └── rustscan_scripts.toml
└── logs/
    └── script_execution.log
```

### Configuración de Seguridad

```
# Configuración de seguridad para RSE
[security]
# Solo ejecutar scripts en estos directorios
allowed_directories = [
    "~/.rustscan/scripts",
    "/opt/rustscan/scripts"
]

# Hash de scripts aprobados (opcional)
approved_scripts = [
    "abc123...http_scanner.py",
    "def456...ssh_audit.py"
]

# Usuarios permitidos para ejecutar scripts
allowed_users = ["security", "pentester"]

# Timeout máximo para scripts
max_timeout = 60

# Límite de recursos
max_memory = "100MB"
max_cpu_time = 30

### Logging y Monitoreo

python

#!/usr/bin/env python3
# logging_wrapper.py

import sys
import logging
import json
from datetime import datetime

def setup_logging():
    """Configurar sistema de logging para scripts RSE"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('/var/log/rustscan_scripts.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )
    return logging.getLogger(__name__)

def log_execution(script_name, ip, port, result):
    """Registrar ejecución de script"""
    logger = setup_logging()
    
    log_entry = {
        'timestamp': datetime.now().isoformat(),
        'script': script_name,
        'target': f"{ip}:{port}",
        'result': result
    }
    
    logger.info(json.dumps(log_entry))
```

---

## 🐛 Troubleshooting

### Problemas Comunes y Soluciones

```
# 1. Scripts no se ejecutan
# Verificar configuración
rustscan -a 192.168.1.1 --scripts list

# Verificar permisos
chmod +x ~/.rustscan/scripts/*.py

# 2. Timeout en scripts
# Aumentar timeout en configuración
echo 'script_timeout = 60' >> ~/.rustscan_scripts.toml

# 3. Scripts con errores
# Modo debug
RUST_LOG=debug rustscan -a 192.168.1.1 --scripts custom

# 4. Problemas de permisos
# Ejecutar con usuario apropiado
sudo -u rustscan-user rustscan -a 192.168.1.1 --scripts default

### Comandos de Diagnóstico RSE

bash

# Listar scripts disponibles
rustscan --scripts list

# Probar script específico
rustscan -a 127.0.0.1 --scripts test --script-name http_scanner.py

# Ver configuración actual
rustscan --scripts config

# Limpiar cache de scripts
rustscan --scripts clean-cache

```
---