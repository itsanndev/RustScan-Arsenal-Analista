## 🎯 Índice
1. Filosofía de Integración
2. Integración con Nmap
3. Pipelines de Seguridad Automatizados
4. Integración con Herramientas Web
5. Integración con Escáneres de Vulnerabilidades
6. Integración con Frameworks de Pentesting
7. Integración con SIEM y Monitoring
8. Integración en CI/CD
9. Scripts de Integración Avanzados


---

## 🔗 Filosofía de Integración

### El Ecosistema RustScan
RustScan está diseñado para ser el **acelerador** en pipelines de seguridad, no para reemplazar herramientas existentes. Su integración nativa con otras herramientas lo convierte en el componente perfecto para workflows automatizados.

### Patrones Comunes de Integración

```
# PATRÓN 1: Pipe directo
rustscan -a 192.168.1.1 | herramienta_externa

# PATRÓN 2: Procesamiento intermedio  
rustscan -a 192.168.1.1 --greppable | procesar | herramienta_externa

# PATRÓN 3: Integración via scripts RSE
rustscan -a 192.168.1.1 --scripts custom

# PATRÓN 4: Pipeline completo
rustscan -> procesamiento -> análisis -> reporting
```

---

## 🔄 Integración con Nmap

### Integración Nativa vs Manual

```
#!/bin/bash
# nmap-integration-comparison.sh

TARGET="192.168.1.1"

echo "🔗 COMPARATIVA: INTEGRACIÓN NMAP"

# 1. INTEGRACIÓN NATIVA (Recomendada)
echo ""
echo "1. 🎯 Integración nativa de RustScan:"
echo "   rustscan -a $TARGET -- -sC -sV -A"
echo "   • Ventaja: Automática, optimizada"
echo "   • Uso: Pentesting diario, auditorías rápidas"

# 2. PIPELINE MANUAL (Para control granular)
echo ""
echo "2. 🔧 Pipeline manual:"
echo "   rustscan -a $TARGET --greppable | grep open | cut -d'/' -f1 | tr '\\n' ',' | xargs -I{} nmap -p{} -sC -sV $TARGET"
echo "   • Ventaja: Control total sobre parámetros Nmap"
echo "   • Uso: Escaneos especializados, entornos complejos"

# 3. INTEGRACIÓN AVANZADA CON FILTRADO
echo ""
echo "3. 🚀 Integración avanzada con filtrado:"
cat << 'EOF'
rustscan -a $TARGET --greppable | \
awk -F'/' '/open/ {print $1}' | \
sort -n | \
tr '\n' ',' | \
sed 's/,$//' | \
xargs -I{} nmap -p{} -sC -sV --script "http-*" $TARGET
EOF
echo "   • Ventaja: Filtrado inteligente por servicio"
echo "   • Uso: Auditorías específicas por protocolo"

```
### Script de Integración Avanzada Nmap
```
#!/usr/bin/env python3
# advanced-nmap-integration.py

import subprocess
import json
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

class AdvancedNmapIntegration:
    def __init__(self, target):
        self.target = target
        self.results = {}
        self.nmap_profiles = {
            'web_servers': {
                'ports': [80, 443, 8080, 8443],
                'scripts': ['http-enum', 'http-vuln-*', 'http-headers'],
                'options': '-sV --script-timeout 30'
            },
            'database_servers': {
                'ports': [1433, 1521, 3306, 5432, 27017],
                'scripts': ['oracle-enum-users', 'mysql-audit', 'pgsql-brute'],
                'options': '-sV --script-timeout 45'
            },
            'network_services': {
                'ports': [21, 22, 23, 25, 53, 110, 143, 993, 995],
                'scripts': ['ftp-anon', 'ssh-auth-methods', 'smtp-commands'],
                'options': '-sV'
            },
            'windows_services': {
                'ports': [135, 139, 445, 3389],
                'scripts': ['smb-enum-shares', 'smb-vuln-*', 'rdp-enum-encryption'],
                'options': '-sV --script-timeout 30'
            }
        }
    
    def rustscan_discovery(self):
        """Descubrimiento rápido con RustScan"""
        print(f"EJECUTANDO DESCUBRIMIENTO RAPIDO EN {self.target}")
        
        cmd = f"rustscan -a {self.target} --timeout 1500 -b 10000 --greppable"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        open_ports = []
        for line in result.stdout.split('\n'):
            if '/open/' in line:
                port = int(line.split('/')[0])
                open_ports.append(port)
        
        self.results['discovery'] = {
            'open_ports': open_ports,
            'total_ports': len(open_ports)
        }
        
        print(f"PUERTOS ABIERTOS ENCONTRADOS: {len(open_ports)}")
        return open_ports
    
    def categorize_ports(self, open_ports):
        """Categorizar puertos por servicio"""
        categorized = {category: [] for category in self.nmap_profiles}
        categorized['other'] = []
        
        for port in open_ports:
            categorized_flag = False
            for category, profile in self.nmap_profiles.items():
                if port in profile['ports']:
                    categorized[category].append(port)
                    categorized_flag = True
                    break
            
            if not categorized_flag:
                categorized['other'].append(port)
        
        return categorized
    
    def run_nmap_scan(self, category, ports):
        """Ejecutar escaneo Nmap especializado"""
        if not ports:
            return None
        
        profile = self.nmap_profiles.get(category, {})
        scripts = profile.get('scripts', ['default'])
        options = profile.get('options', '-sV')
        
        ports_str = ','.join(map(str, ports))
        scripts_str = ','.join(scripts)
        
        cmd = f"nmap -p {ports_str} {options} --script {scripts_str} {self.target}"
        
        print(f"EJECUTANDO ESCANEO DE CATEGORIA {category} EN PUERTOS: 
        {ports_str}")
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        return {
            'category': category,
            'ports': ports,
            'command': cmd,
            'output': result.stdout,
            'returncode': result.returncode
        }
    
    def comprehensive_scan(self):
        """Escaneo completo integrado"""
        # Fase 1: Descubrimiento con RustScan
        open_ports = self.rustscan_discovery()
        
        if not open_ports:
            print("NO SE ENCONTRARON PUERTOS ABIERTOS")
            return
        
        # Fase 2: Categorización
        categorized_ports = self.categorize_ports(open_ports)
        
        # Fase 3: Escaneos especializados en paralelo
        print("EJECUTANDO ESCANEOS NMAP...")
        
        with ThreadPoolExecutor(max_workers=3) as executor:
            future_to_category = {}
            
            for category, ports in categorized_ports.items():
                if ports:  # Solo escanear categorías con puertos
                    future = executor.submit(self.run_nmap_scan, category, ports)
                    future_to_category[future] = category
            
            # Recolectar resultados
            for future in as_completed(future_to_category):
                category = future_to_category[future]
                try:
                    result = future.result()
                    if result:
                        self.results[category] = result
                        print(f"COMPLETADO: {category}")
                except Exception as e:
                    print(f"ERROR EN {category}: {e}")
        
        # Fase 4: Generar reporte consolidado
        self.generate_report()
    
    def generate_report(self):
        """Generar reporte de integración"""
        report = {
            'target': self.target,
            'scan_summary': self.results.get('discovery', {}),
            'detailed_scans': {}
        }
        
        for category, scan_data in self.results.items():
            if category != 'discovery' and scan_data:
                report['detailed_scans'][category] = {
                    'ports_scanned': scan_data['ports'],
                    'command_used': scan_data['command']
                }
        
        # Guardar reporte JSON
        with open(f'nmap_integration_report_{self.target}.json', 'w') as f:
            json.dump(report, f, indent=2)
        
        # Reporte legible
        print(f"\nREPORTE DE INTEGRACIÓN RUSTSCAN-NMAP")
        print("=" * 50)
        print(f"Objetivo: {self.target}")
        print(f"Puertos abiertos totales: {report['scan_summary'].get('total_ports', 0)}")
        
        for category, scan_info in report['detailed_scans'].items():
            print(f"\n{category.upper()}:")
            print(f"  Puertos: {scan_info['ports_scanned']}")
        
        print(f"\nREPORTE DETALLADO: nmap_integration_report_{self.target}.json")

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.1"
    integrator = AdvancedNmapIntegration(target)
    integrator.comprehensive_scan()

```
---

## 🤖 Pipelines de Seguridad Automatizados

### Pipeline Completo de Pentesting
```
#!/bin/bash
# complete-security-pipeline.sh

TARGET="${1:-192.168.1.0/24}"
OUTPUT_DIR="pipeline_$(date +%Y%m%d_%H%M%S)"
LOG_FILE="$OUTPUT_DIR/pipeline.log"

mkdir -p "$OUTPUT_DIR"
exec > >(tee -a "$LOG_FILE") 2>&1

echo "BINICIANDO PIPELINE DE SEGURIDAD AUTOMATIZADO"
echo "Target: $TARGET"
echo "Output: $OUTPUT_DIR"
echo "Log: $LOG_FILE"

# FUNCIÓN: Logging consistente
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# FASE 1: DESCUBRIMIENTO DE ACTIVOS
log "FASE 1: Descubrimiento de activos con RustScan"
rustscan -a "$TARGET" --timeout 2000 -b 15000 --greppable > "$OUTPUT_DIR/1_rustscan_discovery.txt"

# Extraer hosts activos
grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' "$OUTPUT_DIR/1_rustscan_discovery.txt" | sort -u > "$OUTPUT_DIR/2_live_hosts.txt"
LIVE_HOSTS_COUNT=$(wc -l < "$OUTPUT_DIR/2_live_hosts.txt")
log "HOST ACTIVOS ENCONTRADOS: $LIVE_HOSTS_COUNT"

# FASE 2: ESCANEO DE SERVICIOS
log "FASE 2: Escaneo de servicios con RustScan + Nmap"
while IFS= read -r host; do
    log "   Escaneando $host..."
    
    # RustScan rápido + Nmap específico
    rustscan -a "$host" --timeout 1500 -- -sC -sV -O -A -oA "$OUTPUT_DIR/3_service_scan_$host" &
    
    # Control de concurrencia
    background_jobs=$(jobs -rp | wc -l)
    while [ "$background_jobs" -ge 5 ]; do
        sleep 2
        background_jobs=$(jobs -rp | wc -l)
    done
done < "$OUTPUT_DIR/2_live_hosts.txt"

wait
log "ESCANEO DE SERVICIOS COMPLETADO"

# FASE 3: DETECCIÓN DE SERVICIOS WEB
log "FASE 3: Detección de servicios web"
WEB_HOSTS_FILE="$OUTPUT_DIR/4_web_hosts.txt"
> "$WEB_HOSTS_FILE"

while IFS= read -r host; do
    if grep -q "80/open\|443/open\|8080/open\|8443/open" "$OUTPUT_DIR/3_service_scan_$host.nmap" 2>/dev/null; then
        echo "$host" >> "$WEB_HOSTS_FILE"
    fi
done < "$OUTPUT_DIR/2_live_hosts.txt"

WEB_HOSTS_COUNT=$(wc -l < "$WEB_HOSTS_FILE")
log "HOSTS WEB IDENTIFICADOS: $WEB_HOSTS_COUNT"

# FASE 4: ANÁLISIS DE VULNERABILIDADES WEB
if [ "$WEB_HOSTS_COUNT" -gt 0 ]; then
    log "FASE 4: Análisis de vulnerabilidades web"
    
    while IFS= read -r host; do
        log "   Analizando vulnerabilidades en $host..."
        
        # Nuclei para escaneo rápido de vulnerabilidades
        if command -v nuclei &> /dev/null; then
            nuclei -u "http://$host" -t exposures/ -o "$OUTPUT_DIR/5_nuclei_$host.txt" -silent &
        fi
        
        # WhatWeb para fingerprinting
        if command -v whatweb &> /dev/null; then
            whatweb "http://$host" --color=never > "$OUTPUT_DIR/6_whatweb_$host.txt" 2>&1 &
        fi
    done < "$WEB_HOSTS_FILE"
    
    wait
    log "ANALISIS WEB COMPLETADO"
fi

# FASE 5: GENERACIÓN DE REPORTES
log "FASE 5: Generación de reportes consolidados"

# Reporte ejecutivo
{
    echo "PIPELINE DE SEGURIDAD - REPORTE EJECUTIVO"
    echo "=========================================="
    echo "Fecha: $(date)"
    echo "Target: $TARGET"
    echo ""
    echo "RESUMEN EJECUTIVO:"
    echo "- Hosts activos identificados: $LIVE_HOSTS_COUNT"
    echo "- Servicios web detectados: $WEB_HOSTS_COUNT"
    echo "- Escaneos completados: $(find "$OUTPUT_DIR" -name "3_service_scan_*.nmap" | wc -l)"
    echo ""
    echo "HALLazgos PRINCIPALES:"
    find "$OUTPUT_DIR" -name "3_service_scan_*.nmap" -exec grep -h "open" {} \; | sort -u | head -20
    echo ""
    echo "ARCHIVOS GENERADOS:"
    find "$OUTPUT_DIR" -type f -name "*.txt" -o -name "*.nmap" | sort
} > "$OUTPUT_DIR/7_executive_report.txt"

log "PIPELINE COMPLETADO EXITOSAMENTE"
echo "RESULTADOS EN: $OUTPUT_DIR"
echo "REPORTE EJECUTIVO: $OUTPUT_DIR/7_executive_report.txt"
```

---

## 🌐 Integración con Herramientas Web
### Pipeline Automatizado de Análisis Web
```
#!/usr/bin/env python3
# web-analysis-pipeline.py

import subprocess
import json
import sys
import os
from urllib.parse import urljoin
import concurrent.futures
import requests

class WebAnalysisPipeline:
    def __init__(self, target_file):
        self.target_file = target_file
        self.results = {}
        self.tools_available = self.check_tools_availability()
    
    def check_tools_availability(self):
        """Verificar disponibilidad de herramientas"""
        tools = {
            'nuclei': False,
            'whatweb': False,
            'gobuster': False,
            'nikto': False,
            'subfinder': False
        }
        
        for tool in tools:
            if subprocess.run(f"which {tool}", shell=True, capture_output=True).returncode == 0:
                tools[tool] = True
                print(f"{tool} DISPONIBLE")
            else:
                print(f"{tool} no disponible")
        
        return tools
    
    def discover_web_services(self):
        """Descubrir servicios web con RustScan"""
        print("Descubriendo servicios web...")
        
        # Usar RustScan para encontrar puertos web
        cmd = f"rustscan -a - -p 80,443,8080,8443,3000,5000,8000,9000 --greppable < {self.target_file}"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        web_services = []
        for line in result.stdout.split('\n'):
            if '/open/' in line:
                parts = line.split()
                ip = parts[0]
                port = parts[1].split('/')[0]
                protocol = 'https' if port in ['443', '8443'] else 'http'
                url = f"{protocol}://{ip}:{port}"
                web_services.append({'ip': ip, 'port': port, 'url': url})
        
        print(f"SERVICIOS WEB ENCONTRADOS: {len(web_services)}")
        return web_services
    
    def run_whatweb_scan(self, web_service):
        """Ejecutar WhatWeb para fingerprinting"""
        if not self.tools_available['whatweb']:
            return None
        
        try:
            cmd = f"whatweb --color=never {web_service['url']}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            return result.stdout.strip()
        except subprocess.TimeoutExpired:
            return "TIMEOUT"
        except Exception as e:
            return f"ERROR: {str(e)}"
    
    def run_nuclei_scan(self, web_service):
        """Ejecutar Nuclei para vulnerabilidades"""
        if not self.tools_available['nuclei']:
            return None
        
        try:
            cmd = f"nuclei -u {web_service['url']} -t exposures/ -silent"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
            return result.stdout.strip().split('\n') if result.stdout.strip() else []
        except subprocess.TimeoutExpired:
            return ["SCAN_TIMEOUT"]
        except Exception as e:
            return [f"ERROR: {str(e)}"]
    
    def run_gobuster_scan(self, web_service):
        """Ejecutar GoBuster para directory busting"""
        if not self.tools_available['gobuster']:
            return None
        
        try:
            output_file = f"gobuster_{web_service['ip']}_{web_service['port']}.txt"
            cmd = f"gobuster dir -u {web_service['url']} -w /usr/share/wordlists/dirb/common.txt -t 20 -o {output_file}"
            subprocess.run(cmd, shell=True, timeout=120)
            
            # Leer resultados
            with open(output_file, 'r') as f:
                return f.read().strip()
        except Exception as e:
            return f"ERROR: {str(e)}"
    
    def comprehensive_web_analysis(self):
        """Análisis web completo"""
        web_services = self.discover_web_services()
        
        if not web_services:
            print("NO SE ENCONTRARON SERVICIOS WEB")
            return
        
        print(f"EJECUTANDO ANALISIS EN {len(web_services)}")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            for service in web_services:
                print(f"ANALIZANDO: {service['url']}")
                
                # Ejecutar herramientas en paralelo
                future_whatweb = executor.submit(self.run_whatweb_scan, service)
                future_nuclei = executor.submit(self.run_nuclei_scan, service)
                future_gobuster = executor.submit(self.run_gobuster_scan, service)
                
                # Recolectar resultados
                service['whatweb'] = future_whatweb.result()
                service['nuclei'] = future_nuclei.result()
                service['gobuster'] = future_gobuster.result()
                
                self.results[service['url']] = service
        
        self.generate_web_report()
    
    def generate_web_report(self):
        """Generar reporte web consolidado"""
        report = {
            'scan_info': {
                'target_file': self.target_file,
                'web_services_found': len(self.results),
                'tools_used': {k: v for k, v in self.tools_available.items() if v}
            },
            'results': self.results
        }
        
        # Guardar reporte JSON
        with open('web_analysis_report.json', 'w') as f:
            json.dump(report, f, indent=2)
        
        # Reporte legible
        print("\nREPORTE DE ANÁLISIS WEB")
        print("=" * 50)
        
        for url, data in self.results.items():
            print(f"\n web: {url}")
            print(f"   IP: {data['ip']}, Puerto: {data['port']}")
            
            if data.get('whatweb'):
                print(f"   WhatWeb: {data['whatweb'][:100]}...")
            
            if data.get('nuclei') and len(data['nuclei']) > 0:
                print(f"   Nuclei: {len(data['nuclei'])} hallazgos")
                for finding in data['nuclei'][:3]:  # Mostrar primeros 3
                    print(f"     - {finding}")
        
        print(f"\nREPORTE COMPLETO: web_analysis_report.json")

if __name__ == "__main__":
    target_file = sys.argv[1] if len(sys.argv) > 1 else "targets.txt"
    
    if not os.path.exists(target_file):
        print(f"ARCHIVO {target_file} no encontrado")
        sys.exit(1)
    
    pipeline = WebAnalysisPipeline(target_file)
    pipeline.comprehensive_web_analysis()

```
---

## 🛡️ Integración con Escáneres de Vulnerabilidades

### Pipeline Integrado de Vulnerabilidades
```
#!/bin/bash
# vulnerability-scanning-pipeline.sh

TARGETS_FILE="${1:-targets.txt}"
OUTPUT_DIR="vuln_scan_$(date +%Y%m%d_%H%M%S)"
RUSTSCAN_OPTS="--timeout 2000 -b 10000 --greppable"

mkdir -p "$OUTPUT_DIR"
echo "INICIANDO PIPELINE DE VULNERABILIDADES"

# Verificar herramientas disponibles
check_tool() {
    if command -v "$1" &> /dev/null; then
        echo " $1 DISPONIBLE"
        return 0
    else
        echo "$1 no disponible"
        return 1
    fi
}

echo "🔧 Verificando herramientas..."
check_tool rustscan
check_tool nmap
check_tool nuclei
check_tool sslscan
check_tool nikto

echo "Fase 1: Descubrimiento de servicios"
rustscan -a "-" $RUSTSCAN_OPTS < "$TARGETS_FILE" > "$OUTPUT_DIR/1_discovery.txt"

# Extraer servicios por categoría
echo "CATEGORIZANDO SERVICIOS"
> "$OUTPUT_DIR/2_web_services.txt"
> "$OUTPUT_DIR/2_ssl_services.txt"
> "$OUTPUT_DIR/2_ssh_services.txt"

while read -r line; do
    if [[ $line =~ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+).*([0-9]+)/open ]]; then
        ip="${BASH_REMATCH[1]}"
        port="${BASH_REMATCH[2]}"
        
        case $port in
            80|443|8080|8443)
                echo "$ip:$port" >> "$OUTPUT_DIR/2_web_services.txt"
                ;;
            443|8443|993|995)
                echo "$ip:$port" >> "$OUTPUT_DIR/2_ssl_services.txt"
                ;;
            22)
                echo "$ip:$port" >> "$OUTPUT_DIR/2_ssh_services.txt"
                ;;
        esac
    fi
done < "$OUTPUT_DIR/1_discovery.txt"

if [[ -s "$OUTPUT_DIR/2_web_services.txt" ]]; then
    echo "Fase 2: Escaneo de vulnerabilidades web"
    
    # Nuclei para vulnerabilidades comunes
    if check_tool nuclei; then
        echo "   Ejecutando Nuclei..."
        while IFS=: read -r ip port; do
            protocol="https" && [[ $port == "80" || $port == "8080" ]] && protocol="http"
            url="$protocol://$ip:$port"
            nuclei -u "$url" -t exposures/ -o "$OUTPUT_DIR/3_nuclei_${ip}_${port}.txt" -silent &
        done < "$OUTPUT_DIR/2_web_services.txt"
        wait
    fi
    
    # Nikto para análisis de servidores web
    if check_tool nikto; then
        echo "   Ejecutando Nikto..."
        while IFS=: read -r ip port; do
            nikto -h "$ip" -p "$port" -o "$OUTPUT_DIR/3_nikto_${ip}_${port}.txt" -Format txt &
        done < "$OUTPUT_DIR/2_web_services.txt"
        wait
    fi
fi

# Fase 3: Análisis SSL/TLS
if [[ -s "$OUTPUT_DIR/2_ssl_services.txt" ]] && check_tool sslscan; then
    echo "Fase 3: Análisis SSL/TLS"
    while IFS=: read -r ip port; do
        sslscan "$ip:$port" > "$OUTPUT_DIR/3_sslscan_${ip}_${port}.txt" &
    done < "$OUTPUT_DIR/2_ssl_services.txt"
    wait
fi

# Fase 4: Análisis SSH
if [[ -s "$OUTPUT_DIR/2_ssh_services.txt" ]]; then
    echo "Fase 4: Análisis SSH"
    while IFS=: read -r ip port; do
        nmap -p "$port" --script "ssh2-enum-algos,ssh-auth-methods,ssh-hostkey" "$ip" > "$OUTPUT_DIR/3_ssh_scan_${ip}.txt" &
    done < "$OUTPUT_DIR/2_ssh_services.txt"
    wait
fi

# Fase 5: Reporte consolidado
echo "Fase 5: Generando reporte consolidado"

{
    echo "VULNERABILITY SCANNING PIPELINE REPORT"
    echo "======================================"
    echo "Fecha: $(date)"
    echo "Targets: $(cat "$TARGETS_FILE" | wc -l) objetivos"
    echo ""
    echo "RESUMEN DE HALLazgos:"
    echo ""
    echo "SERVICIOS WEB ANALIZADOS: $(cat "$OUTPUT_DIR/2_web_services.txt" 2>/dev/null | wc -l || echo 0)"
    find "$OUTPUT_DIR" -name "3_nuclei_*.txt" -exec grep -h "\[.*\]" {} \; | head -10
    echo ""
    echo "SERVICIOS SSL ANALIZADOS: $(cat "$OUTPUT_DIR/2_ssl_services.txt" 2>/dev/null | wc -l || echo 0)"
    find "$OUTPUT_DIR" -name "3_sslscan_*.txt" -exec grep -h "Not After" {} \; | head -5
    echo ""
    echo "SERVICIOS SSH ANALIZADOS: $(cat "$OUTPUT_DIR/2_ssh_services.txt" 2>/dev/null | wc -l || echo 0)"
    find "$OUTPUT_DIR" -name "3_ssh_scan_*.txt" -exec grep -h "ssh-" {} \; | head -5
} > "$OUTPUT_DIR/4_final_report.txt"

echo "PIPELINE DE VULNERABILIDADES COMPLETADO"
echo "RESULTADOS EN: $OUTPUT_DIR"

```
---

## ⚔️ Integración con Frameworks de Pentesting

### Integración con Metasploit
```
#!/usr/bin/env python3
# metasploit-integration.py

import subprocess
import xml.etree.ElementTree as ET
import json
import sys

class MetasploitIntegration:
    def __init__(self, target):
        self.target = target
        self.open_ports = []
        self.services = []
    
    def rustscan_discovery(self):
        """Descubrimiento con RustScan y output XML para parsing"""
        print(f"Descubriendo servicios en {self.target}")
        
        cmd = f"rustscan -a {self.target} -- -sV -oX {self.target}_scan.xml"
        subprocess.run(cmd, shell=True, capture_output=True)
        
        # Parsear resultados XML
        try:
            tree = ET.parse(f'{self.target}_scan.xml')
            root = tree.getroot()
            
            for host in root.findall('host'):
                for port in host.findall('ports/port'):
                    if port.find('state').get('state') == 'open':
                        port_id = port.get('portid')
                        service = port.find('service')
                        service_name = service.get('name') if service is not None else 'unknown'
                        
                        self.open_ports.append(port_id)
                        self.services.append({
                            'port': port_id,
                            'service': service_name,
                            'product': service.get('product', ''),
                            'version': service.get('version', '')
                        })
            
            print(f"SERVICIOS ENCONTRADOS: {len(self.services)}")
            
        except Exception as e:
            print(f"ERROR PARSEANDO RESULTADOS: {e}")
    
    def generate_metasploit_rc(self):
        """Generar archivo .rc para Metasploit"""
        rc_commands = [
            "use auxiliary/scanner/portscan/tcp",
            f"set RHOSTS {self.target}",
            "set PORTS " + ",".join(self.open_ports),
            "run",
            ""
        ]
        
        # Agregar módulos específicos por servicio
        for service in self.services:
            if service['service'] == 'http' or service['service'] == 'https':
                rc_commands.extend([
                    "use auxiliary/scanner/http/http_version",
                    f"set RHOSTS {self.target}",
                    f"set RPORT {service['port']}",
                    "run",
                    ""
                ])
            elif service['service'] == 'ssh':
                rc_commands.extend([
                    "use auxiliary/scanner/ssh/ssh_version", 
                    f"set RHOSTS {self.target}",
                    f"set RPORT {service['port']}",
                    "run",
                    ""
                ])
            elif service['service'] == 'ftp':
                rc_commands.extend([
                    "use auxiliary/scanner/ftp/ftp_version",
                    f"set RHOSTS {self.target}",
                    f"set RPORT {service['port']}",
                    "run",
                    ""
                ])
        
        rc_commands.append("exit")
        
        # Escribir archivo .rc
        rc_file = f"{self.target}_metasploit.rc"
        with open(rc_file, 'w') as f:
            f.write("\n".join(rc_commands))
        
        print(f"ARCHIVO METASPLOIT GENERADO: {rc_file}")
        return rc_file
    
    def run_metasploit_scan(self):
        """Ejecutar escaneo con Metasploit"""
        rc_file = self.generate_metasploit_rc()
        
        print("EJECUTANDO METASPLOIT")
        cmd = f"msfconsole -r {rc_file}"
        
        try:
            # Ejecutar y capturar output
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
            print("METASPLOIT REALIZADO")
            
            # Guardar output
            with open(f"{self.target}_metasploit_output.txt", 'w') as f:
                f.write(result.stdout)
            
            return result.stdout
        except subprocess.TimeoutExpired:
            print(METASPLOIT FALLIDO / TIMEOUT")
            return "TIMEOUT"

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.1"
    
    integrator = MetasploitIntegration(target)
    integrator.rustscan_discovery()
    
    if integrator.open_ports:
        integrator.run_metasploit_scan()
    else:
        print("NO HAY PUERTOS ABIERTOS PARA ANALIZAR")

```
### Integración con Empire/Starkiller
```
#!/bin/bash
# empire-integration.sh

TARGET="$1"
LISTENER_NAME="rustscan_$(date +%s)"

echo "⚔️ INTEGRACIÓN CON EMPIRE"

# Descubrimiento con RustScan
echo "DESCUBRIMIENTO"
rustscan -a "$TARGET" --greppable > rustscan_results.txt

# Generar lista de objetivos para Empire
echo "LISTA DE OBJETIVOS"
awk '/open/ {print $1 ":" $2}' rustscan_results.txt | sed 's/\/.*//' > empire_targets.txt
cat empire_targets.txt

# Crear listener en Empire (ejemplo conceptual)
echo "📡 Configurando listener en Empire..."
cat << EOF > empire_listener.txt
uselistener http
set Name $LISTENER_NAME
set Host http://$(hostname -I | awk '{print $1}')
set Port 8080
execute
EOF

echo "INTEGRACIÓN CON EMPIRE COMPLETADA"
echo "ARCHIVOS GENERADOS:"
echo "   - rustscan_results.txt"
echo "   - empire_targets.txt" 
echo "   - empire_listener.txt"

```
---

## 📊 Integración con SIEM y Monitoring

### Script de Exportación a ELK Stack
```
#!/usr/bin/env python3
# elk-export-integration.py

import json
import subprocess
import sys
from datetime import datetime
import requests

class ELKIntegration:
    def __init__(self, elasticsearch_host="http://localhost:9200"):
        self.es_host = elasticsearch_host
        self.index_name = f"rustscan-scans-{datetime.now().strftime('%Y-%m')}"
    
    def run_rustscan(self, target):
        """Ejecutar RustScan y obtener resultados estructurados"""
        print(f"RUSTCAN EJECUTANDOSE EN {target}")
        
        cmd = f"rustscan -a {target} --greppable"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        scan_results = {
            'timestamp': datetime.now().isoformat(),
            'target': target,
            'scan_type': 'tcp_connect',
            'results': []
        }
        
        for line in result.stdout.split('\n'):
            if '/open/' in line:
                parts = line.split()
                if len(parts) >= 2:
                    ip = parts[0]
                    port_proto = parts[1].split('/')
                    if len(port_proto) == 2:
                        scan_results['results'].append({
                            'host': ip,
                            'port': int(port_proto[0]),
                            'protocol': port_proto[1],
                            'state': 'open'
                        })
        
        return scan_results
    
    def create_elasticsearch_index(self):
        """Crear índice en Elasticsearch si no existe"""
        mapping = {
            "mappings": {
                "properties": {
                    "timestamp": {"type": "date"},
                    "target": {"type": "keyword"},
                    "scan_type": {"type": "keyword"},
                    "results": {
                        "type": "nested",
                        "properties": {
                            "host": {"type": "ip"},
                            "port": {"type": "integer"},
                            "protocol": {"type": "keyword"},
                            "state": {"type": "keyword"}
                        }
                    }
                }
            }
        }
        
        try:
            response = requests.put(f"{self.es_host}/{self.index_name}", json=mapping)
            if response.status_code in [200, 201]:
                print(f"INDICE CREADO: {self.index_name}")
            else:
                print(f"INDICE PREEXISTENTE: {response.status_code}")
        except Exception as e:
            print(f"INDICE FALLIDO: {e}")
    
    def send_to_elasticsearch(self, scan_data):
        """Enviar datos a Elasticsearch"""
        try:
            response = requests.post(
                f"{self.es_host}/{self.index_name}/_doc",
                json=scan_data,
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code in [200, 201]:
                print(f"DATOS ENVIADOS A ELASTICSEARCH")
                return True
            else:
                print(f"ERROR ENVIANDO DATOS: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"ERROR DE CONEXION: {e}")
            return False
    
    def export_scan(self, target):
        """Ejecutar escaneo y exportar a ELK"""
        # Crear índice
        self.create_elasticsearch_index()
        
        # Ejecutar escaneo
        scan_data = self.run_rustscan(target)
        
        # Enviar a Elasticsearch
        if self.send_to_elasticsearch(scan_data):
            print("ESCANEO EXPORTADO EXITOSAMENTE ELK")
        else:
            # Guardar localmente como fallback
            filename = f"scan_export_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(filename, 'w') as f:
                json.dump(scan_data, f, indent=2)
            print(f"DATOS GUARDADOS LOCALMENTE: {filename}")

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.0/24"
    es_host = sys.argv[2] if len(sys.argv) > 2 else "http://localhost:9200"
    
    elk = ELKIntegration(es_host)
    elk.export_scan(target)

```
### Integración con Splunk
```
#!/bin/bash
# splunk-integration.sh

TARGET="$1"
SPLUNK_HEC_URL="${2:-https://splunk-server:8088/services/collector}"
SPLUNK_TOKEN="${3:-YOUR_SPLUNK_TOKEN}"

echo "INTEGRACIÓN CON SPLUNK"

# Ejecutar RustScan y formatear para Splunk
echo "EJECUTANDO ESCANEO..."
rustscan -a "$TARGET" --greppable | \
awk -F'/' '
/open/ {
    print "{\"time\": \"'$(date +%s)'\", \"host\": \"" $1 "\", \"sourcetype\": \"rustscan\", \"event\": {\"target\": \"'$TARGET'\", \"ip\": \"" $1 "\", \"port\": \"" $2 "\", \"protocol\": \"" $3 "\", \"status\": \"open\"}}"
}' > splunk_data.json

echo "ENVIANDO DATOS A SPLUNK..."
while IFS= read -r line; do
    curl -k "$SPLUNK_HEC_URL" \
        -H "Authorization: Splunk $SPLUNK_TOKEN" \
        -d "$line" \
        > /dev/null 2>&1
    
    echo -n "."
done < splunk_data.json

echo ""
echo "DATOS ENVIADOS A SPLUNK"
echo "DATOS LOCALES: splunk_data.json"

```
---

## 🔄 Integración en CI/CD

### GitHub Actions para Escaneos de Seguridad

```
# .github/workflows/security-scan.yml
name: Security Scan with RustScan

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]
  schedule:
    - cron: '0 0 * * 0'  # Weekly scan

jobs:
  network-security-scan:
    runs-on: ubuntu-latest
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v3
      
    - name: Setup RustScan
      run: |
        wget -q -O rustscan.deb https://github.com/RustScan/RustScan/releases/download/2.1.1/rustscan_2.1.1_amd64.deb
        sudo dpkg -i rustscan.deb
        sudo apt-get install -y nmap
        
    - name: Run security scan
      run: |
        # Escanear servicios de la aplicación
        rustscan -a ${{ secrets.SCANNING_TARGET }} --timeout 2000 -- -sC -sV -oA security-scan
        
        # Verificar resultados
        if grep -q "80/open" security-scan.nmap; then
          echo "HTTP service DETECTADO"
        else
          echo "HTTP service NO ENCONTRADO"
          exit 1
        fi
        
    - name: Upload scan results
      uses: actions/upload-artifact@v3
      with:
        name: security-scan-results
        path: |
          security-scan.nmap
          security-scan.xml
        retention-days: 30
        
    - name: Security check
      run: |
        # Buscar servicios inseguros
        if grep -E "23/open|135/open|139/open" security-scan.nmap; then
          echo "SERVICIOS INSEGUROS DETECTADOS"
          exit 1
        else
          echo "NO SE ENCONTRARON SERVICIOS INSEGUROS"
        fi
```

### GitLab CI Pipeline
```
# .gitlab-ci.yml
stages:
  - security_scan

rustscan_security_audit:
  stage: security_scan
  image: rustscan/rustscan:latest
  services:
    - docker:dind
  script:
    # Instalar dependencias
    - apk add --no-cache nmap curl jq
    
    # Ejecutar escaneo de seguridad
    - rustscan -a $SCAN_TARGETS --timeout 1500 -- -sC -sV -A -oX scan_results.xml
    
    # Procesar resultados
    - |
      if [ -f scan_results.xml ]; then
        echo "SCAN RESULTS SUMMARY:"
        grep -oP '(?<=portid=")[^"]*(?=" protocol)' scan_results.xml | sort -n | uniq -c
        
        # Verificar servicios críticos
        CRITICAL_PORTS="80 443 22"
        for port in $CRITICAL_PORTS; do
          if grep -q "portid=\"$port\"" scan_results.xml; then
            echo "PUERTO $port ESTA ABIERTO"
          else
            echo "PUERTO $port ESTA CERRADO"
          fi
        done
      fi
    
    # Generar reporte
    - |
      {
        echo "# Security Scan Report"
        echo "## Target: $SCAN_TARGETS"
        echo "## Date: $(date)"
        echo ""
        echo "## PUERTOS ABIERTOS:"
        grep -oP '(?<=portid=")[^"]*(?=" protocol)' scan_results.xml | sort -n
      } > security_report.md
  artifacts:
    paths:
      - scan_results.xml
      - security_report.md
    reports:
      junit: scan_results.xml
  only:
    - schedules
    - web
```

---

## 🛠️ Scripts de Integración Avanzados

### Orquestador de Seguridad Unificado
```
#!/usr/bin/env python3
# security-orchestrator.py

import yaml
import subprocess
import json
import sys
from pathlib import Path
from datetime import datetime

class SecurityOrchestrator:
    def __init__(self, config_file="orchestrator-config.yaml"):
        self.config = self.load_config(config_file)
        self.results = {}
    
    def load_config(self, config_file):
        """Cargar configuración del orquestador"""
        default_config = {
            'scanning': {
                'rustscan': {
                    'enabled': True,
                    'timeout': 2000,
                    'batch_size': 10000,
                    'scripts': 'default'
                }
            },
            'integration': {
                'nmap': {'enabled': True},
                'nuclei': {'enabled': True},
                'metasploit': {'enabled': False},
                'elasticsearch': {'enabled': False}
            },
            'reporting': {
                'formats': ['json', 'html', 'markdown'],
                'output_dir': './security_reports'
            }
        }
        
        if Path(config_file).exists():
            with open(config_file, 'r') as f:
                user_config = yaml.safe_load(f)
                # Merge con configuración default
                return self.merge_dicts(default_config, user_config)
        
        return default_config
    
    def merge_dicts(self, dict1, dict2):
        """Fusionar diccionarios recursivamente"""
        result = dict1.copy()
        for key, value in dict2.items():
            if isinstance(value, dict) and key in result and isinstance(result[key], dict):
                result[key] = self.merge_dicts(result[key], value)
            else:
                result[key] = value
        return result
    
    def run_rustscan_phase(self, target):
        """Ejecutar fase de descubrimiento con RustScan"""
        if not self.config['scanning']['rustscan']['enabled']:
            return None
        
        print("Fase 1: Descubrimiento con RustScan")
        
        rustscan_config = self.config['scanning']['rustscan']
        cmd = f"rustscan -a {target} --timeout {rustscan_config['timeout']} -b {rustscan_config['batch_size']}"
        
        if rustscan_config.get('scripts'):
            cmd += f" --scripts {rustscan_config['scripts']}"
        
        # Ejecutar RustScan
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        # Procesar resultados
        open_ports = []
        for line in result.stdout.split('\n'):
            if '/open/' in line:
                parts = line.split()
                if len(parts) >= 2:
                    ip = parts[0]
                    port = parts[1].split('/')[0]
                    open_ports.append({'ip': ip, 'port': port})
        
        self.results['rustscan'] = {
            'target': target,
            'open_ports': open_ports,
            'timestamp': datetime.now().isoformat()
        }
        
        print(f"PUERTOS ABIERTOS ENCONTRAODS: {len(open_ports)}")
        return open_ports
    
    def run_integration_phase(self, target, open_ports):
        """Ejecutar fase de integración con otras herramientas"""
        print("🔗 Fase 2: Integración con herramientas de seguridad")
        
        integration_results = {}
        
        # Integración con Nmap
        if self.config['integration']['nmap']['enabled'] and open_ports:
            integration_results['nmap'] = self.run_nmap_integration(target, open_ports)
        
        # Integración con Nuclei (para servicios web)
        if self.config['integration']['nuclei']['enabled']:
            integration_results['nuclei'] = self.run_nuclei_integration(target, open_ports)
        
        self.results['integration'] = integration_results
        return integration_results
    
    def run_nmap_integration(self, target, open_ports):
        """Integración con Nmap"""
        print("ANALISIS CON NMAP")
        
        ports_str = ','.join([port_info['port'] for port_info in open_ports])
        cmd = f"nmap -p {ports_str} -sC -sV -A {target} -oX nmap_results.xml"
        
        subprocess.run(cmd, shell=True, capture_output=True)
        
        # Parsear resultados XML de Nmap
        try:
            import xml.etree.ElementTree as ET
            tree = ET.parse('nmap_results.xml')
            root = tree.getroot()
            
            nmap_results = []
            for host in root.findall('host'):
                for port in host.findall('ports/port'):
                    if port.find('state').get('state') == 'open':
                        service_info = {
                            'port': port.get('portid'),
                            'protocol': port.get('protocol'),
                            'service': port.find('service').get('name') if port.find('service') is not None else 'unknown'
                        }
                        nmap_results.append(service_info)
            
            return nmap_results
        except Exception as e:
            return {'error': str(e)}
    
    def run_nuclei_integration(self, target, open_ports):
        """Integración con Nuclei"""
        print("ESCANEO NUCLEI.")
        
        # Encontrar servicios web
        web_ports = [p for p in open_ports if p['port'] in ['80', '443', '8080', '8443']]
        
        if not web_ports:
            return {'message': 'No web services found'}
        
        nuclei_results = []
        for port_info in web_ports:
            protocol = 'https' if port_info['port'] in ['443', '8443'] else 'http'
            url = f"{protocol}://{port_info['ip']}:{port_info['port']}"
            
            cmd = f"nuclei -u {url} -t exposures/ -silent"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.stdout.strip():
                nuclei_results.append({
                    'url': url,
                    'findings': result.stdout.strip().split('\n')
                })
        
        return nuclei_results
    
    def generate_reports(self):
        """Generar reportes en múltiples formatos"""
        print("Fase 3: Generación de reportes")
        
        output_dir = Path(self.config['reporting']['output_dir'])
        output_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # JSON Report
        if 'json' in self.config['reporting']['formats']:
            json_file = output_dir / f"security_scan_{timestamp}.json"
            with open(json_file, 'w') as f:
                json.dump(self.results, f, indent=2)
            print(f"REPORTE COMPLETADO / JSON: {json_file}")
        
        # Markdown Report
        if 'markdown' in self.config['reporting']['formats']:
            md_file = output_dir / f"security_scan_{timestamp}.md"
            self.generate_markdown_report(md_file)
            print(f"REPORTE COMPLETADO / MARKDOWN: {md_file}")
        
        # HTML Report (simplificado)
        if 'html' in self.config['reporting']['formats']:
            html_file = output_dir / f"security_scan_{timestamp}.html"
            self.generate_html_report(html_file)
            print(f"REPORTE COMPLETADO / HTML: {html_file}")
    
    def generate_markdown_report(self, filename):
        """Generar reporte en Markdown"""
        with open(filename, 'w') as f:
            f.write("# Security Scan Report\n\n")
            f.write(f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            if 'rustscan' in self.results:
                rustscan_data = self.results['rustscan']
                f.write("## RustScan Results\n\n")
                f.write(f"- **Target:** {rustscan_data['target']}\n")
                f.write(f"- **Open Ports:** {len(rustscan_data['open_ports'])}\n\n")
                
                for port_info in rustscan_data['open_ports']:
                    f.write(f"  - {port_info['ip']}:{port_info['port']}\n")
            
            if 'integration' in self.results:
                f.write("\n## Integration Results\n\n")
                
                for tool, results in self.results['integration'].items():
                    f.write(f"### {tool.upper()}\n\n")
                    if isinstance(results, list):
                        f.write(f"- Findings: {len(results)}\n")
                    else:
                        f.write("- Results available in detailed report\n")
    
    def generate_html_report(self, filename):
        """Generar reporte HTML básico"""
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Security Scan Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                .header {{ background: #f4f4f4; padding: 20px; border-radius: 5px; }}
                .section {{ margin: 20px 0; }}
                .port {{ background: #e9e9e9; padding: 5px; margin: 2px; display: inline-block; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Security Scan Report</h1>
                <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
        """
        
        if 'rustscan' in self.results:
            html_content += f"""
            <div class="section">
                <h2>RustScan Results</h2>
                <p><strong>Target:</strong> {self.results['rustscan']['target']}</p>
                <p><strong>Open Ports:</strong> {len(self.results['rustscan']['open_ports'])}</p>
                <div>
            """
            
            for port_info in self.results['rustscan']['open_ports']:
                html_content += f'<span class="port">{port_info["ip"]}:{port_info["port"]}</span>'
            
            html_content += "</div></div>"
        
        html_content += """
            </div>
        </body>
        </html>
        """
        
        with open(filename, 'w') as f:
            f.write(html_content)
    
    def run_complete_scan(self, target):
        """Ejecutar escaneo completo"""
        print(f"INICIANDO ORQUESTACIÓN DE SEGURIDAD")
        print(f"Objetivo: {target}")
        print(f"Configuración: {json.dumps(self.config, indent=2)}")
        print("=" * 50)
        
        # Fase 1: Descubrimiento
        open_ports = self.run_rustscan_phase(target)
        
        if not open_ports:
            print("NO se encontraron puertos abiertos")
            return
        
        # Fase 2: Integración
        self.run_integration_phase(target, open_ports)
        
        # Fase 3: Reportes
        self.generate_reports()
        
        print("ORQUESTACIÓN COMPLETADA EXITOSAMENTE")

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.1"
    config_file = sys.argv[2] if len(sys.argv) > 2 else "orchestrator-config.yaml"
    
    orchestrator = SecurityOrchestrator(config_file)
    orchestrator.run_complete_scan(target)

```
---
