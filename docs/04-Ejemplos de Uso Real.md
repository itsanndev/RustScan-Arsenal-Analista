
## 🎯 Índice
1. [Pentesting Interno](#pentesting-interno)
2. [Auditorías de Compliance](#auditorías-de-compliance)
3. [Respuesta a Incidentes](#respuesta-a-incidentes)
4. [Monitoreo Continuo](#monitoreo-continuo)
5. [CTFs y Entornos Educativos](#ctfs-y-entornos-educativos)
6. [Red Teams](#red-teams)
7. [DevSecOps](#devsecops)

---

<a id="pentesting-interno"></a>
## 🏢 Pentesting Interno

### Escenario 1: Evaluación de Red Corporativa

**Contexto:** Auditoría de seguridad interna en red 10.0.0.0/16 con 500+ hosts.

```
#!/bin/bash
# pentest-internal.sh

NETWORK="10.0.0.0/16"
OUTPUT_DIR="internal_audit_$(date +%Y%m%d)"
mkdir -p "$OUTPUT_DIR"

echo "Descubrimiento rápido de activos"
rustscan -a "$NETWORK" --timeout 2000 -b 10000 --greppable > "$OUTPUT_DIR/1_discovery_raw.txt"

# Filtrar hosts activos
grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' "$OUTPUT_DIR/1_discovery_raw.txt" | sort -u > "$OUTPUT_DIR/2_live_hosts.txt"

echo "Escaneo detallado por segmentos"
while IFS= read -r host; do
    echo "Escaneando $host..."
    rustscan -a "$host" --timeout 1500 -b 5000 -- -sC -sV -O -A -oA "$OUTPUT_DIR/3_scan_$host" &
    
    # Limitar a 10 escaneos simultáneos
    ((count=count+1))
    if (( count % 10 == 0 )); then
        wait
    fi
done < "$OUTPUT_DIR/2_live_hosts.txt"

wait

echo "Análisis de servicios críticos"
find "$OUTPUT_DIR" -name "*.xml" -exec grep -l "80/open\|443/open\|22/open\|3389/open" {} \; | \
xargs -I{} basename {} | sed 's/3_scan_//' | sed 's/.xml//' > "$OUTPUT_DIR/4_critical_hosts.txt"

echo "TEST PRELIMINAR COMPLETADO: $OUTPUT_DIR"

```
### Escenario 2: Evaluación de Servidores Críticos

**Contexto:** Análisis profundo de servidores DMZ y críticos.
```
#!/bin/bash
# critical-servers-scan.sh

SERVERS=("web01.example.com" "db01.example.com" "app01.example.com" "192.168.1.100")
OUTPUT_DIR="critical_servers_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTPUT_DIR"

for server in "${SERVERS[@]}"; do
    echo "Escaneando servidor crítico: $server"
    
    # Escaneo completo con todos los scripts de seguridad
    rustscan -a "$server" --timeout 3000 -- -A -sC -sV --script "safe,vuln,discovery" -oA "$OUTPUT_DIR/full_scan_${server//./_}"
    
    # Escaneo específico por tipo de servidor
    if [[ $server == *"web"* ]]; then
        echo "Ejecutando escaneo web específico..."
        rustscan -a "$server" -p 80,443,8080,8443 -- --script "http-*" -oA "$OUTPUT_DIR/web_scan_${server//./_}"
    fi
    
    if [[ $server == *"db"* ]]; then
        echo "Ejecutando escaneo de bases de datos..."
        rustscan -a "$server" -p 1433,1521,3306,5432,27017 -- --script "oracle*,mysql*,postgres*" -oA "$OUTPUT_DIR/db_scan_${server//./_}"
    fi
done

# Generar reporte consolidado
echo "📋 Generando reporte consolidado..."
find "$OUTPUT_DIR" -name "*.nmap" -exec cat {} \; > "$OUTPUT_DIR/consolidated_report.txt"

echo "ESCANEO DE SERVIDORES CRITICOS COMPLETADO"
```

---

<a id="auditorías-de-compliance"></a>
## 📋 Auditorías de Compliance

### Escenario 3: Cumplimiento de Estándares CIS
**Contexto:** Verificación de configuración según Center for Internet Security.

```
#!/bin/bash
# cis-compliance-audit.sh

TARGETS_FILE="cis_targets.txt"
CIS_OUTPUT="cis_audit_$(date +%Y%m%d)"
mkdir -p "$CIS_OUTPUT"

echo "INICIANDO TESTEO DE AUDITORIA"

cis_scan() {
    local target=$1
    echo "Auditando $target contra estándares CIS..."
    
    # CIS Controls: Network Monitoring and Defense
    rustscan -a "$target" -- -p 1-1000 --script "cisco*,snmp-info" -oA "$CIS_OUTPUT/cis_network_$target"
    
    # CIS Controls: Inventory and Control of Software Assets
    rustscan -a "$target" -- -sV --version-intensity 7 -oA "$CIS_OUTPUT/cis_inventory_$target"
    
    # CIS Controls: Secure Configuration
    rustscan -a "$target" -p 22,23,3389 -- --script "ssh*,telnet*,rdp*" -oA "$CIS_OUTPUT/cis_config_$target"
}

export -f cis_scan
export CIS_OUTPUT

# Ejecutar en paralelo para múltiples objetivos
cat "$TARGETS_FILE" | xargs -I{} -P 5 bash -c 'cis_scan "$@"' _ {}

echo "Generando reporte de cumplimiento CIS..."
echo "CIS Compliance Audit Report" > "$CIS_OUTPUT/cis_summary.md"
echo "===========================" >> "$CIS_OUTPUT/cis_summary.md"
echo "Fecha: $(date)" >> "$CIS_OUTPUT/cis_summary.md"
echo "" >> "$CIS_OUTPUT/cis_summary.md"

for target in $(cat "$TARGETS_FILE"); do
    echo "### $target" >> "$CIS_OUTPUT/cis_summary.md"
    grep -h "open" "$CIS_OUTPUT/cis_network_${target}.nmap" | head -10 >> "$CIS_OUTPUT/cis_summary.md"
    echo "" >> "$CIS_OUTPUT/cis_summary.md"
done

echo "Auditoría CIS completada: $CIS_OUTPUT"
```

### Escenario 4: Validación de Hardening

**Contexto:** Verificación de hardening post-implementación.

```
#!/usr/bin/env python3
# hardening-validation.py

import subprocess
import json
import sys
from datetime import datetime

class HardeningValidator:
    def __init__(self, targets):
        self.targets = targets
        self.results = {}
        self.hardening_checks = {
            'ssh': [22],
            'web': [80, 443, 8080, 8443],
            'database': [1433, 1521, 3306, 5432, 27017],
            'management': [23, 135, 139, 445, 3389]
        }
    
    def check_service_hardening(self, target, port, service):
        """Verificar hardening específico por servicio"""
        checks = {
            'ssh': f"rustscan -a {target} -p {port} -- --script ssh2-enum-algos,ssh-auth-methods -oN {target}_ssh_check.txt",
            'web': f"rustscan -a {target} -p {port} -- --script http-security-headers -oN {target}_web_check.txt",
            'database': f"rustscan -a {target} -p {port} -- --script mysql-audit -oN {target}_db_check.txt"
        }
        
        if service in checks:
            subprocess.run(checks[service], shell=True, capture_output=True)
    
    def run_validation(self):
        """Ejecutar validación completa de hardening"""
        print("Iniciando validación de hardening...")
        
        for target in self.targets:
            self.results[target] = {}
            print(f"Validando {target}...")
            
            for service, ports in self.hardening_checks.items():
                # Escanear puertos del servicio
                cmd = f"rustscan -a {target} -p {','.join(map(str, ports))} --greppable"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                
                open_ports = []
                for line in result.stdout.split('\n'):
                    if f'{ports[0]}/open' in line:  # Solo verificar el puerto principal
                        open_ports.append(ports[0])
                        self.check_service_hardening(target, ports[0], service)
                
                self.results[target][service] = {
                    'ports_checked': ports,
                    'open_ports': open_ports,
                    'status': 'HARDENED' if not open_ports else 'NEEDS_REVIEW'
                }
        
        self.generate_report()
    
    def generate_report(self):
        """Generar reporte de hardening"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'validation_results': self.results
        }
        
        with open('hardening_validation_report.json', 'w') as f:
            json.dump(report, f, indent=2)
        
        print("Reporte generado: hardening_validation_report.json")

if __name__ == "__main__":
    targets = sys.argv[1:] if len(sys.argv) > 1 else ['192.168.1.1']
    validator = HardeningValidator(targets)
    validator.run_validation()

```
---

<a id="respuesta-a-incidentes"></a>
## 🚨 Respuesta a Incidentes

### Escenario 5: Investigación de Compromiso

**Contexto:** Respuesta rápida a posible breach en segmento de red.

```
#!/bin/bash
# incident-response.sh

INCIDENT_NETWORK="192.168.100.0/24"
INCIDENT_ID="IR_$(date +%Y%m%d_%H%M%S)"
EVIDENCE_DIR="/evidence/$INCIDENT_ID"

mkdir -p "$EVIDENCE_DIR"
echo "IDENTIFICADOR - RESPUESTA INCIDENTE: $INCIDENT_ID"

# Fase 1: Reconocimiento rápido del segmento comprometido
echo "Fase 1: Mapeo rápido del segmento comprometido"
rustscan -a "$INCIDENT_NETWORK" --timeout 1000 -b 20000 --scan-order Random --greppable > "$EVIDENCE_DIR/1_network_snapshot.txt"

echo "Fase 2: Búsqueda de servicios sospechosos"
SUSPICIOUS_PORTS="4444,5555,6666,6667,1337,31337,12345,54321,9999,10000,20000,30000,40000,50000"

rustscan -a "$INCIDENT_NETWORK" -p "$SUSPICIOUS_PORTS" --greppable > "$EVIDENCE_DIR/2_suspicious_ports.txt"

echo "Fase 3: Escaneo de backdoors conocidos"
BACKDOOR_PORTS="1234,4321,9999,10000,20000,30000,31337,54321,60000,65000"

rustscan -a "$INCIDENT_NETWORK" -p "$BACKDOOR_PORTS" -- --script "malware*,backdoor*" -oA "$EVIDENCE_DIR/3_backdoor_scan"

echo "Fase 4: Análisis de servicios web"
rustscan -a "$INCIDENT_NETWORK" -p 80,443,8080,8443 -- --script "http-malware-host,http-slowloris-check" -oA "$EVIDENCE_DIR/4_web_analysis"

# Generar timeline del incidente
echo "TimeLine Forense"
{
    echo "INCIDENT RESPONSE TIMELINE"
    echo "=========================="
    echo "Incident ID: $INCIDENT_ID"
    echo "Start Time: $(date)"
    echo "Network: $INCIDENT_NETWORK"
    echo ""
    echo "HOSTS ACTIVOS:"
    grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' "$EVIDENCE_DIR/1_network_snapshot.txt" | sort -u
    echo ""
    echo "PUERTOS SOSPECHOSOS DETECTADOS:"
    cat "$EVIDENCE_DIR/2_suspicious_ports.txt"
} > "$EVIDENCE_DIR/incident_timeline.txt"

echo "RESPUESTA INCIDENTE COMPLETADA: $EVIDENCE_DIR"
```

### Escenario 6: Detección de Movimiento Lateral
**Contexto:** Monitoreo de actividad sospechosa post-compromiso.

```
#!/usr/bin/env python3
# lateral-movement-detector.py

import subprocess
import json
import time
from datetime import datetime, timedelta

class LateralMovementDetector:
    def __init__(self, network_segments):
        self.segments = network_segments
        self.baseline = {}
        self.current_scan = {}
        self.alerts = []
    
    def establish_baseline(self):
        """Establecer línea base de servicios normales"""
        print("Estableciendo línea base de red...")
        
        for segment in self.segments:
            cmd = f"rustscan -a {segment} --timeout 2000 -b 5000 --greppable"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            services = {}
            for line in result.stdout.split('\n'):
                if '/open/' in line:
                    parts = line.split()
                    ip = parts[0]
                    port = parts[1].split('/')[0]
                    
                    if ip not in services:
                        services[ip] = []
                    services[ip].append(port)
            
            self.baseline[segment] = services
            print(f"Línea base establecida para {segment}: {sum(len(v) for v in services.values())} servicios")
        
        # Guardar línea base
        with open('network_baseline.json', 'w') as f:
            json.dump({
                'timestamp': datetime.now().isoformat(),
                'baseline': self.baseline
            }, f, indent=2)
    
    def detect_changes(self):
        """Detectar cambios desde la línea base"""
        print("Detectando cambios en la red...")
        
        for segment in self.segments:
            cmd = f"rustscan -a {segment} --timeout 2000 -b 5000 --greppable"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            current_services = {}
            for line in result.stdout.split('\n'):
                if '/open/' in line:
                    parts = line.split()
                    ip = parts[0]
                    port = parts[1].split('/')[0]
                    
                    if ip not in current_services:
                        current_services[ip] = []
                    current_services[ip].append(port)
            
            # Comparar con línea base
            baseline_services = self.baseline.get(segment, {})
            
            for ip, ports in current_services.items():
                baseline_ports = set(baseline_services.get(ip, []))
                current_ports = set(ports)
                
                # Detectar nuevos servicios
                new_ports = current_ports - baseline_ports
                if new_ports:
                    alert = {
                        'type': 'NEW_SERVICE',
                        'segment': segment,
                        'host': ip,
                        'new_ports': list(new_ports),
                        'timestamp': datetime.now().isoformat()
                    }
                    self.alerts.append(alert)
                    print(f"ALERTA: Nuevos servicios en {ip}: {new_ports}")
    
    def continuous_monitoring(self, interval_minutes=5):
        """Monitoreo continuo"""
        self.establish_baseline()
        
        print(f"Iniciando monitoreo continuo (intervalo: {interval_minutes} minutos)")
        
        try:
            while True:
                self.detect_changes()
                
                # Guardar alertas
                if self.alerts:
                    with open('lateral_movement_alerts.json', 'w') as f:
                        json.dump(self.alerts, f, indent=2)
                
                time.sleep(interval_minutes * 60)
                
        except KeyboardInterrupt:
            print("\nMonitoreo detenido")

if __name__ == "__main__":
    # Segmentos de red a monitorear
    segments = ["192.168.1.0/24", "192.168.2.0/24", "10.0.1.0/24"]
    
    detector = LateralMovementDetector(segments)
    detector.continuous_monitoring(interval_minutes=10)
```

---

<a id="monitoreo-continuo"></a>
## 📊 Monitoreo Continuo

### Escenario 7: Dashboard de Servicios

**Contexto:** Monitoreo continuo de servicios críticos.

```
#!/bin/bash
# service-monitoring-dashboard.sh

CRITICAL_SERVICES=(
    "web:80,443"
    "database:3306,5432,1433"
    "ssh:22"
    "dns:53"
    "mail:25,110,143,993,995"
)

MONITOR_DIR="/monitoring/$(date +%Y%m)"
mkdir -p "$MONITOR_DIR"

echo "MONITOREO DE SERVICIOS CRITICOS..."

monitor_services() {
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local output_file="$MONITOR_DIR/services_$timestamp.json"
    
    echo "{" > "$output_file"
    echo '  "timestamp": "'$timestamp'",' >> "$output_file"
    echo '  "services": [' >> "$output_file"
    
    for service in "${CRITICAL_SERVICES[@]}"; do
        IFS=':' read -r service_name ports <<< "$service"
        
        echo "    {" >> "$output_file"
        echo '      "name": "'$service_name'",' >> "$output_file"
        echo '      "ports": "'$ports'",' >> "$output_file"
        echo '      "status": "' >> "$output_file"
        
        # Verificar servicios
        rustscan -a "192.168.1.0/24" -p "$ports" --greppable 2>/dev/null | \
        grep "/open/" | head -5 >> "$output_file"
        
        echo '"' >> "$output_file"
        echo "    }," >> "$output_file"
    done
    
    echo "  ]" >> "$output_file"
    echo "}" >> "$output_file"
    
    echo "SNAPSHOT GUARDADO: $output_file"
}

# Ejecutar monitoreo cada hora
while true; do
    monitor_services
    sleep 3600  # 1 hora
done

```
---

<a id="ctfs-y-entornos-educativos"></a>
## 🎯 CTFs y Entornos Educativos

### Escenario 8: Automatización para CTFs

```
#!/usr/bin/env python3
# ctf-automation.py

import subprocess
import re
import json

class CTFAutomation:
    def __init__(self, target):
        self.target = target
        self.findings = []
    
    def full_ctf_scan(self):
        """Escaneo completo para CTFs"""
        print(f"INICIANDO ESCANEO CTF PARA {self.target}")
        
        print("FASE 1 ESCANEO RAPIDO DE TODOS LOS PUERTOS")
        self.quick_port_scan()
        
        print("ANALISIS DE SERVICIOS")
        self.service_analysis()
        
        print("BUSQUEDA DE VULNERABILIDADES CTF")
        self.ctf_vulnerability_scan()
        
        self.generate_ctf_report()
    
    def quick_port_scan(self):
        """Escaneo rápido de puertos"""
        cmd = f"rustscan -a {self.target} --timeout 1000 -b 20000 --greppable"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        open_ports = []
        for line in result.stdout.split('\n'):
            if '/open/' in line:
                port = line.split('/')[0]
                open_ports.append(port)
        
        self.findings.append({
            'type': 'open_ports',
            'ports': open_ports
        })
        
        print(f"PUERTOS ABIERTOS: {', '.join(open_ports)}")
    
    def service_analysis(self):
        """Análisis detallado de servicios"""
        open_ports = self.findings[0]['ports']
        if not open_ports:
            return
        
        ports_str = ','.join(open_ports)
        
        # Escaneo de versiones y scripts básicos
        cmd = f"rustscan -a {self.target} -p {ports_str} -- -sC -sV --script safe -oA ctf_services"
        subprocess.run(cmd, shell=True)
    
    def ctf_vulnerability_scan(self):
        """Escaneo específico para vulnerabilidades comunes en CTFs"""
        ctf_scripts = [
            "http-enum",           # Enumeración web
            "ftp-anon",            # FTP anónimo
            "ssh-auth-methods",    # Métodos de autenticación SSH
            "smb-enum-shares",     # Shares SMB
            "snmp-brute",          # SNMP
            "redis-info",          # Redis
            "mongodb-info",        # MongoDB
        ]
        
        for script in ctf_scripts:
            cmd = f"rustscan -a {self.target} -- --script {script}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if "VULNERABLE" in result.stdout or "anonymous" in result.stdout.lower():
                self.findings.append({
                    'type': 'ctf_finding',
                    'script': script,
                    'output': result.stdout[:500]  # Primeros 500 caracteres
                })
    
    def generate_ctf_report(self):
        """Generar reporte amigable para CTF"""
        report = {
            'target': self.target,
            'findings': self.findings,
            'next_steps': self.suggest_next_steps()
        }
        
        with open(f'ctf_report_{self.target}.json', 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"RRPORTE CTF GENERADO: ctf_report_{self.target}.json")
    
    def suggest_next_steps(self):
        """Sugerir siguientes pasos basados en findings"""
        suggestions = []
        open_ports = self.findings[0]['ports'] if self.findings else []
        
        if '80' in open_ports or '443' in open_ports:
            suggestions.append("ALERTA Investigar servicio web: navegador, dirb, nikto")
        
        if '21' in open_ports:
            suggestions.append("ALERTA Verificar FTP: anonymous login, enumeración")
        
        if '22' in open_ports:
            suggestions.append("ALERTA Investigar SSH: version, auth methods, brute force")
        
        if '445' in open_ports or '139' in open_ports:
            suggestions.append("ALERTA Verificar SMB: enum4linux, smbclient")
        
        return suggestions

if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.100"
    
    ctf = CTFAutomation(target)
    ctf.full_ctf_scan()
```

---

<a id="red-teams"></a>
## 🔴 Red Teams

### Escenario 9: Operaciones de Red Team

```
#!/bin/bash
# red-team-operations.sh

# Configuración operacional
TARGET_ORG="target-corp.com"
OPERATION_ID="RT_$(date +%Y%m%d_%H%M%S)"
LOG_DIR="/opt/redteam/$OPERATION_ID"

mkdir -p "$LOG_DIR"
echo "INICIANDO TEST DE OPERACION RED TEAMERS: $OPERATION_ID"

echo "RECONOCIMIENTO EXTERNO"
rustscan -a "$TARGET_ORG" --timeout 3000 -b 5000 --scan-order Random --greppable > "$LOG_DIR/1_external_recon.txt"

echo "ESCANEO SIGILOSO"
KNOWN_RANGES=("203.0.113.0/24" "198.51.100.0/24" "192.0.2.0/24")

for range in "${KNOWN_RANGES[@]}"; do
    echo "   Escaneando $range..."
    rustscan -a "$range" --timeout 5000 -b 1000 --scan-order Random --delay 100 --greppable >> "$LOG_DIR/2_stealth_scan.txt" 2>/dev/null &
    sleep 5  # Espaciar escaneos
done

wait
e
echo "IDENTIFICACION DE VECTORES"
rustscan -a "$TARGET_ORG" -p 80,443,8080,8443 -- --script "http-enum,http-vuln*" -oA "$LOG_DIR/3_web_vectors" 2>/dev/null

echo "TECNICAS DE EVASION"
# Escaneo con timing aleatorio y fragmentación
rustscan -a "$TARGET_ORG" --timeout $(shuf -i 1000-5000 -n 1) -b $(shuf -i 500-2000 -n 1) --scan-order Random --fragment --greppable > "$LOG_DIR/4_evasion_scan.txt"

# Generar reporte operacional
echo "GENERANDO REPORTE RED TEAM"
{
    echo "RED TEAM OPERATION REPORT"
    echo "========================"
    echo "Operation ID: $OPERATION_ID"
    echo "Target: $TARGET_ORG"
    echo "Date: $(date)"
    echo ""
    echo "EXTERNAL ASSETS IDENTIFIED:"
    grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' "$LOG_DIR/1_external_recon.txt" | sort -u
    echo ""
    echo "POTENTIAL ATTACK VECTORS:"
    grep -h "VULNERABLE\|WEAK\|anonymous" "$LOG_DIR"/*.nmap 2>/dev/null | head -10
} > "$LOG_DIR/red_team_report.txt"

echo "OPERACION RED TEAMERS COMPLETADA: $LOG_DIR"

```
---

<a id="devsecops"></a>
## 🔧 DevSecOps

### Escenario 10: Pipeline de Seguridad CI/CD

```
# .gitlab-ci.yml
stages:
  - security_scan

rustscan_security_scan:
  stage: security_scan
  image: rustscan/rustscan:latest
  script:
    # Escaneo de servicios de desarrollo
    - rustscan -a $STAGING_SERVER --timeout 2000 -b 5000 --greppable > scan_results.txt
    
    # Análisis de puertos expuestos
    - |
      if grep -q "80/open\|443/open\|22/open" scan_results.txt; then
        echo "SERVICIOS ESENCIALES DETECTADOS"
      else
        echo "SERVICIOS ESENCIALES NO DETECTADOS"
        exit 1
      fi
    
    # Verificación de puertos no autorizados
    - |
      UNAUTHORIZED_PORTS=$(grep -E "23/open|135/open|139/open|445/open" scan_results.txt || true)
      if [ -n "$UNAUTHORIZED_PORTS" ]; then
        echo "🚨 Puertos no autorizados detectados:"
        echo "$UNAUTHORIZED_PORTS"
        exit 1
      fi
    
    # Reporte de seguridad
    - echo "REPORTE DE SEGURIDAD:" && cat scan_results.txt
  artifacts:
    paths:
      - scan_results.txt
    when: always
  only:
    - main
    - staging

python

#!/usr/bin/env python3
# devsecops-pipeline.py

import subprocess
import json
import sys

class DevSecOpsScanner:
    def __init__(self, environment):
        self.environment = environment
        self.scan_results = {}
        self.security_thresholds = {
            'max_open_ports': 20,
            'banned_ports': [23, 135, 139, 445, 3389],  # Telnet, RPC, SMB, RDP
            'required_ports': [80, 443]  # HTTP/HTTPS para servicios web
        }
    
    def run_security_scan(self, target):
        """Ejecutar escaneo de seguridad"""
        print(f"EJECUTANDO ESCANEO DE SEGURIDAD {target}")
        
        # Escaneo completo
        cmd = f"rustscan -a {target} --timeout 1500 -b 8000 --greppable"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        # Procesar resultados
        open_ports = []
        for line in result.stdout.split('\n'):
            if '/open/' in line:
                port = int(line.split('/')[0])
                open_ports.append(port)
        
        self.scan_results[target] = {
            'open_ports': open_ports,
            'total_ports': len(open_ports),
            'banned_ports_found': [p for p in open_ports if p in self.security_thresholds['banned_ports']],
            'missing_required_ports': [p for p in self.security_thresholds['required_ports'] if p not in open_ports]
        }
    
    def evaluate_security(self, target):
        """Evaluar cumplimiento de seguridad"""
        results = self.scan_results[target]
        violations = []
        
        # Verificar número de puertos abiertos
        if results['total_ports'] > self.security_thresholds['max_open_ports']:
            violations.append(f"Demasiados puertos abiertos: {results['total_ports']}")
        
        # Verificar puertos prohibidos
        if results['banned_ports_found']:
            violations.append(f"Puertos prohibidos detectados: {results['banned_ports_found']}")
        
        # Verificar puertos requeridos
        if results['missing_required_ports']:
            violations.append(f"Puertos requeridos faltantes: {results['missing_required_ports']}")
        
        return violations
    
    def generate_pipeline_report(self):
        """Generar reporte para pipeline CI/CD"""
        report = {
            'environment': self.environment,
            'timestamp': __import__('datetime').datetime.now().isoformat(),
            'scan_results': self.scan_results,
            'security_assessment': {}
        }
        
        all_violations = []
        for target in self.scan_results:
            violations = self.evaluate_security(target)
            report['security_assessment'][target] = {
                'status': 'PASS' if not violations else 'FAIL',
                'violations': violations
            }
            all_violations.extend(violations)
        
        # Determinar estado general del pipeline
        report['pipeline_status'] = 'SUCCESS' if not all_violations else 'FAILED'
        
        # Guardar reporte
        with open('security_scan_report.json', 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"REPORTE DE SEGURIDAD GENERADO: security_scan_report.json")
        
        # Salir con código apropiado para CI/CD
        sys.exit(0 if not all_violations else 1)

if __name__ == "__main__":
    import os
    
    environment = os.getenv('ENVIRONMENT', 'staging')
    target = os.getenv('TARGET_SERVER', 'staging.example.com')
    
    scanner = DevSecOpsScanner(environment)
    scanner.run_security_scan(target)
    scanner.generate_pipeline_report()

```
---
