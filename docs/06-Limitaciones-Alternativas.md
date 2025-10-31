
## 🎯 Índice

1. [Limitaciones Técnicas de RustScan](#-limitaciones-técnicas-de-rustscan)
2. [Escenarios Donde Otras Herramientas Son Mejores](#escenarios-donde-otras-herramientas-son-mejores)
3. [Comparativa Detallada con Nmap](#-comparativa-detallada-con-nmap)
4. [Comparativa con Masscan y Zmap](#-comparativa-con-masscan-y-zmap)
5. [Estrategias de Combinación](#-estrategias-de-combinación)
6. [Casos de Uso Específicos por Herramienta](#-casos-de-uso-específicos-por-herramienta)
7. [Migración desde Otras Herramientas](#-migración-desde-otras-herramientas)
    
---

<a id="⚠️-limitaciones-técnicas-de-rustscan"></a>
## ⚠️ Limitaciones Técnicas de RustScan

### Limitaciones Actuales (v2.1.1)

```
# !!! FUNCIONALIDADES NO SOPORTADAS !!!

# Escaneo UDP - No soportado
rustscan -a 192.168.1.1 -sU  # Error: UDP not supported

# Escaneo de protocolos específicos
rustscan -a 192.168.1.1 -sA  # No ACK scan
rustscan -a 192.168.1.1 -sW  # No Window scan
rustscan -a 192.168.1.1 -sM  # No Maimon scan

# Técnicas avanzadas de evasión
rustscan -a 192.168.1.1 -f    # Fragmentación limitada
rustscan -a 192.168.1.1 -D    # No decoy scanning
rustscan -a 192.168.1.1 -S    # No IP spoofing

# Output formats limitados
rustscan -a 192.168.1.1 -oX   # Solo formatos básicos
```

### Limitaciones de Rendimiento en Escenarios Específicos
```
# !!! REDES CON ALTA LATENCIA !!!
# RustScan puede tener falsos negativos en redes con >100ms de latency
rustscan -a 203.0.113.0/24 --timeout 5000  # Requiere timeout alto

# !!! FIREWALLS AGRESIVOS !!!
# Detección más fácil que Nmap en firewalls stateful
rustscan -a 192.168.1.1 --scan-order Random --timeout 3000

# !!! SISTEMAS WINDOWS ANTIGUOS !!!
# Puede saturar stacks TCP antiguos
rustscan -a 192.168.1.100 -b 1000 --timeout 2000  # Reducir batch size
```

### Limitaciones de Scripting y Extensibilidad
```
# RSE vs NSE (Nmap Scripting Engine)
# RustScan RSE: Scripting básico post-scan
# Nmap NSE: Scripting durante el escaneo, más de 600 scripts

# Ejemplo de limitación RSE
#!/usr/bin/env python3
# Solo se ejecuta DESPUÉS del escaneo
# No puede modificar el comportamiento del escaneo en tiempo real
```

---

<a id="escenarios-donde-otras-herramientas-son-mejores"></a>
## Escenarios Donde Otras Herramientas Son Mejores


### Cuándo Usar *Nmap* en su lugar

```
#!/bin/bash
# 1. ESCANEOS UDP COMPLETOS
echo "1. Escaneos UDP:"
nmap -sU -sV --top-ports 1000 192.168.1.1

# 2. FINGERPRINTING AVANZADO
echo "2. OS Detection avanzado:"
nmap -O --osscan-guess 192.168.1.1

# 3. TÉCNICAS DE EVASIÓN COMPLEJAS
echo "3. Técnicas avanzadas de evasión:"
nmap -sS -T2 -D RND:10 --source-port 53 --spoof-mac 0 192.168.1.1

# 4. SCRIPTING COMPLEJO DURANTE ESCANEO
echo "4. Scripting en tiempo real:"
nmap --script "http-vuln*" -p 80,443 192.168.1.1

# 5. ESCANEOS DE RED COMPLEJOS
echo "5. Escaneos con múltiples técnicas:"
nmap -sS -sU -O -A -T4 192.168.1.1
```

### Cuándo Usar *Masscan* en su lugar

```
#!/bin/bash

# 1. ESCANEOS INTERNET-SCALE
echo "1. Escaneos de internet completos:"
masscan -p0-65535 0.0.0.0/0 --rate 100000

# 2. MÁXIMA VELOCIDAD EN REDES RÁPIDAS
echo "2. Velocidad extrema en 10Gbps+ networks:"
masscan -p1-65535 192.168.1.0/24 --rate 25000

# 3. ESCANEOS CON RANGOS DE PUERTOS COMPLEJOS
echo "3. Rangos de puertos complejos:"
masscan -p1-1000,5000-6000,U:53,U:161 192.168.1.0/24
```

### Cuándo Usar Herramientas Especializadas
```
#!/bin/bash
# specialized-tools-scenarios.sh

echo "HERRAMIENTAS ESPECIALIZADAS PARA CASOS ESPECÍFICOS"

# 1. ZMAP PARA ESCANEOS INTERNET-WIDE
echo "1. Zmap para estudios de internet:"
zmap -p 80 -o results.txt

# 2. NAABU PARA ESCANEOS RÁPIDOS CON FEATURES MODERNAS
echo "2. Naabu para escaneos rápidos con más opciones:"
naabu -host 192.168.1.1 -silent -verify

# 3. AUTOMAE PARA AUTOMATIZACIÓN COMPLETA
echo "3. Automae para pipelines automatizados:"
automae --target 192.168.1.0/24 --module portscan
```

---

<a id="-comparativa-detallada-con-nmap"></a>
## 📊 Comparativa Detallada con Nmap

### Tabla Comparativa Completa: RustScan vs Nmap

| Característica     | RustScan            | Nmap                  | Ventaja            | Impacto                         |
| ------------------ | ------------------- | --------------------- | ------------------ | ------------------------------- |
| **Velocidad TCP**  | ⚡ 65k puertos en 3s | 🐢 65k puertos en 45s | **RustScan (15x)** | Alto en redes grandes           |
| **Escaneo UDP**    | ❌ No soportado      | ✅ Completo            | **Nmap**           | Crítico para escaneos completos |
| **OS Detection**   | ⚠️ Básico via Nmap  | ✅ Avanzado            | **Nmap**           | Alto para fingerprinting        |
| **Scripting**      | ✅ RSE (Post-scan)   | ✅ NSE (Real-time)     | **Nmap**           | Medio para auditorías           |
| **Evación**        | ✅ Básica            | ✅ Avanzada            | **Nmap**           | Alto en entornos restringidos   |
| **Recursos**       | 🟢 5-15MB RAM       | 🟡 50-200MB RAM       | **RustScan**       | Medio en sistemas limitados     |
| **Output Formats** | ✅ Básicos           | ✅ Completo            | **Nmap**           | Bajo para reporting             |
| **Integración**    | ✅ Nativa con Nmap   | ❌ N/A                 | **RustScan**       | Alto para workflows             |

### Análisis Técnico Profundo
```
#!/usr/bin/env python3
# nmap-vs-rustscan-analysis.py

class ScannerComparison:
    def __init__(self):
        self.feature_matrix = {
            'scan_types': {
                'rustscan': ['TCP Connect', 'SYN Scan (con sudo)'],
                'nmap': ['TCP Connect', 'SYN', 'ACK', 'Window', 'Maimon', 'FIN', 'Null', 'Xmas', 'UDP', 'SCTP']
            },
            'performance': {
                'rustscan': {'tcp_speed': 'Very High', 'resource_usage': 'Low'},
                'nmap': {'tcp_speed': 'Medium', 'resource_usage': 'High'}
            },
            'scripting': {
                'rustscan': {'engine': 'RSE', 'timing': 'Post-scan', 'languages': 'Python, Bash, Perl'},
                'nmap': {'engine': 'NSE', 'timing': 'Real-time', 'languages': 'Lua'}
            },
            'evasion': {
                'rustscan': ['Random order', 'Custom timing', 'Basic fragmentation'],
                'nmap': ['Decoy IPs', 'MAC spoofing', 'Source port manipulation', 'Packet fragmentation', 'Timing templates']
            }
        }
    
    def generate_recommendation(self, use_case):
        """Generar recomendación basada en caso de uso"""
        recommendations = {
            'quick_discovery': {
                'tool': 'RustScan',
                'reason': 'Velocidad extrema para descubrimiento inicial',
                'command': 'rustscan -a 192.168.1.0/24 --timeout 1500'
            },
            'comprehensive_audit': {
                'tool': 'Nmap',
                'reason': 'Escaneo completo con todos los protocolos y scripting',
                'command': 'nmap -sS -sU -O -A -T4 192.168.1.1'
            },
            'stealth_scan': {
                'tool': 'Nmap',
                'reason': 'Técnicas avanzadas de evasión y sigilo',
                'command': 'nmap -sS -T2 -D RND:5 --source-port 53 --spoof-mac 0 192.168.1.1'
            },
            'resource_constrained': {
                'tool': 'RustScan', 
                'reason': 'Bajo consumo de memoria y CPU',
                'command': 'rustscan -a 192.168.1.0/24 -b 5000 --timeout 2000'
            },
            'ctf_environment': {
                'tool': 'Combinación',
                'reason': 'RustScan para descubrimiento rápido + Nmap para análisis',
                'command': 'rustscan -a 192.168.1.100 -- -sC -sV -A'
            }
        }
        
        return recommendations.get(use_case, {})

# Uso del análisis
comparison = ScannerComparison()
print("ANÁLISIS RUSTSCAN vs NMAP")
for category, features in comparison.feature_matrix.items():
    print(f"\n{category.upper()}:")
    for tool, capabilities in features.items():
        print(f"  {tool}: {capabilities}")
```

---

<a id="-comparativa-con-masscan-y-zmap"></a>
## 🚀 Comparativa con Masscan y Zmap

### Tabla Comparativa: Escáneres de Alta Velocidad

|Característica|RustScan|Masscan|Zmap|Ganador|
|---|---|---|---|---|
|**Velocidad Máxima**|⚡ 20k pps|⚡⚡ 100k pps|⚡⚡⚡ 1M+ pps|**Zmap**|
|**Precisión**|🟢 Alta|🟢 Alta|🟡 Media|**RustScan/Masscan**|
|**Facilidad de Uso**|🟢 Muy Fácil|🟡 Media|🔴 Compleja|**RustScan**|
|**Integración**|🟢 Nativa con Nmap|🟡 Manual|🔴 Manual|**RustScan**|
|**Recursos**|🟢 Muy Bajos|🟢 Bajos|🟢 Muy Bajos|**Empate**|
|**Características**|🟡 Básicas|🟡 Básicas|🔴 Mínimas|**RustScan**|

### Análisis de Casos de Uso Específicos
```
#!/bin/bash
# masscan-zmap-comparison.sh

echo "!!! CASOS DE USO ESPECÍFICOS POR HERRAMIENTA !!! "

# 1. RUSTSCAN - Pentesting diario
echo "   rustscan -a 192.168.1.0/24 -- -sC -sV"
echo "   • Descubrimiento rápido + análisis automático"
echo "   • Ideal para redes internas y evaluaciones"

# 2. MASSCAN - Auditorías internet-scale  
echo "   masscan -p80,443 0.0.0.0/0 --rate 10000"
echo "   • Escaneos de puertos específicos a gran escala"
echo "   • Investigación académica y estudios globales"

# 3. ZMAP - Máxima velocidad pura
echo "   zmap -p 443 -o https_servers.txt"
echo "   • Cuando solo importa la velocidad bruta"
echo "   • Estudios de seguridad a escala internet"

# 4. COMBINACIÓN - Enfoque profesional
echo "   # Fase 1: Descubrimiento rápido"
echo "   rustscan -a 10.0.0.0/8 --greppable > targets.txt"
echo "   # Fase 2: Escaneo masivo de puertos específicos"
echo "   masscan -p1-1000 -iL targets.txt --rate 5000"
echo "   # Fase 3: Análisis detallado"
echo "   nmap -sC -sV -A -iL masscan_results.txt"
```

---

<a id="-estrategias-de-combinación"></a>
## 🔄 Estrategias de Combinación

### Pipeline Profesional: Las 3 Herramientas

```
#!/bin/bash
# professional-scanning-pipeline.sh

TARGET_NETWORK="${1:-192.168.1.0/24}"
OUTPUT_DIR="scan_results_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTPUT_DIR"

echo "INICIANDO PIPELINE PROFESIONAL DE ESCANEO"
echo "Objetivo: $TARGET_NETWORK"
echo "Output: $OUTPUT_DIR"

# FASE 1: DESCUBRIMIENTO RÁPIDO CON RUSTSCAN
echo "FASE 1: Descubrimiento rápido con rustcan"
rustscan -a "$TARGET_NETWORK" --timeout 1500 -b 10000 --greppable > "$OUTPUT_DIR/1_rustscan_discovery.txt"

# Extraer hosts activos
grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' "$OUTPUT_DIR/1_rustscan_discovery.txt" | sort -u > "$OUTPUT_DIR/2_live_hosts.txt"

LIVE_HOSTS_COUNT=$(wc -l < "$OUTPUT_DIR/2_live_hosts.txt")
echo "HOSTS ACTIVOS ENCONTRADOS: $LIVE_HOSTS_COUNT"

# FASE 2: ESCANEO MASIVO CON MASSCAN (OPCIONAL PARA REDES GRANDES)
if [ "$LIVE_HOSTS_COUNT" -gt 50 ]; then
    echo "FASE 2: Escaneo masivo con Masscan"
    masscan -p1-1000 -iL "$OUTPUT_DIR/2_live_hosts.txt" --rate 5000 -oG "$OUTPUT_DIR/3_masscan_ports.txt" 2>/dev/null
else
    cp "$OUTPUT_DIR/1_rustscan_discovery.txt" "$OUTPUT_DIR/3_masscan_ports.txt"
fi

# FASE 3: ANÁLISIS DETALLADO CON NMAP
# Procesar resultados para Nmap
awk '/Host:/{print $2}' "$OUTPUT_DIR/3_masscan_ports.txt" | sort -u > "$OUTPUT_DIR/4_nmap_targets.txt"

# Escaneo paralelo con Nmap
echo "Ejecutando escaneos Nmap en paralelo..."
while IFS= read -r host; do
    echo "   Analizando $host..."
    nmap -sC -sV -O -A --script "default,safe" -oA "$OUTPUT_DIR/5_nmap_scan_$host" "$host" &
    
    # Limitar a 5 escaneos simultáneos
    background_jobs=$(jobs -rp | wc -l)
    while [ "$background_jobs" -ge 5 ]; do
        sleep 1
        background_jobs=$(jobs -rp | wc -l)
    done
done < "$OUTPUT_DIR/4_nmap_targets.txt"

# Esperar a que terminen todos los trabajos
wait

# FASE 4: GENERACIÓN DE REPORTES
# Reporte consolidado
{
    echo "PROFESSIONAL SCANNING PIPELINE REPORT"
    echo "====================================="
    echo "Target: $TARGET_NETWORK"
    echo "Date: $(date)"
    echo "Tools: RustScan + Masscan + Nmap"
    echo ""
    echo "SUMMARY:"
    echo "- Hosts activos: $LIVE_HOSTS_COUNT"
    echo "- Escaneos Nmap completados: $(find "$OUTPUT_DIR" -name "5_nmap_scan_*.nmap" | wc -l)"
    echo ""
    echo "DETAILED RESULTS:"
    find "$OUTPUT_DIR" -name "5_nmap_scan_*.nmap" -exec grep -h "open" {} \; | sort -u
} > "$OUTPUT_DIR/6_final_report.txt"

echo "PIPELINE COMPLETADO"
echo "RESULTADOS EN: $OUTPUT_DIR"
echo "REPORTE FINAL: $OUTPUT_DIR/6_final_report.txt"
```

### Estrategia Híbrida para Diferentes Escenarios
```
#!/usr/bin/env python3
# hybrid-scanning-strategy.py

import subprocess
import json
from datetime import datetime

class HybridScanningStrategy:
    def __init__(self, target):
        self.target = target
        self.results = {}
    
    def select_strategy(self, scenario):
        """Seleccionar estrategia basada en el escenario"""
        strategies = {
            'internal_network': self.internal_network_strategy,
            'external_penetration_test': self.external_penetration_test_strategy,
            'compliance_audit': self.compliance_audit_strategy,
            'incident_response': self.incident_response_strategy,
            'ctf_challenge': self.ctf_strategy
        }
        
        return strategies.get(scenario, self.default_strategy)
    
    def internal_network_strategy(self):
        """Estrategia para redes internas"""
        print("ESTRATEGIA EN RED/ES INTERNA/S")
        
        # Fase 1: RustScan rápido para descubrimiento
        cmd = f"rustscan -a {self.target} --timeout 1000 -b 15000 --greppable"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        # Fase 2: Nmap para análisis detallado
        open_ports = self.extract_open_ports(result.stdout)
        if open_ports:
            ports_str = ','.join(open_ports)
            cmd = f"nmap -sC -sV -O -A -p {ports_str} {self.target}"
            subprocess.run(cmd, shell=True)
    
    def external_penetration_test_strategy(self):
        """Estrategia para pentesting externo"""
        print("PENTESTING EXTERNO")
        
        # Fase 1: RustScan sigiloso
        cmd = f"rustscan -a {self.target} --scan-order Random --timeout 3000 -b 1000 --greppable"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        # Fase 2: Nmap con técnicas de evasión
        open_ports = self.extract_open_ports(result.stdout)
        if open_ports:
            ports_str = ','.join(open_ports)
            cmd = f"nmap -sS -T2 -D RND:5 -p {ports_str} --script default,safe {self.target}"
            subprocess.run(cmd, shell=True)
    
    def compliance_audit_strategy(self):
        """Estrategia para auditorías de compliance"""
        print("AUDITORIA DE COMPLIANCE")
        
        # Solo Nmap para reporting completo
        cmd = f"nmap -sS -sU -O -A -T4 --script safe,vuln {self.target}"
        subprocess.run(cmd, shell=True)
    
    def incident_response_strategy(self):
        """Estrategia para respuesta a incidentes"""
        print("RESPUESTA A INCIDENTES")
        
        # RustScan ultra-rápido para evaluación inmediata
        cmd = f"rustscan -a {self.target} --timeout 500 -b 20000 --greppable"
        subprocess.run(cmd, shell=True)
        
        # Escaneo rápido de servicios críticos
        cmd = f"nmap -p 22,80,443,3389,5900 --script malware {self.target}"
        subprocess.run(cmd, shell=True)
    
    def ctf_strategy(self):
        """Estrategia para CTFs"""
        print("ESTRATEGIA PARA CTFS)
        
        # RustScan para descubrimiento rápido
        cmd = f"rustscan -a {self.target} -- -sC -sV -A --script default"
        subprocess.run(cmd, shell=True)
    
    def default_strategy(self):
        """Estrategia por defecto"""
        print("EJECUTANDO ACCIÓN PREDETERMINADA")
        cmd = f"rustscan -a {self.target} -- -sC -sV"
        subprocess.run(cmd, shell=True)
    
    def extract_open_ports(self, rustscan_output):
        """Extraer puertos abiertos del output de RustScan"""
        open_ports = []
        for line in rustscan_output.split('\n'):
            if '/open/' in line:
                port = line.split('/')[0]
                open_ports.append(port)
        return open_ports

# Uso de la estrategia híbrida
if __name__ == "__main__":
    import sys
    
    target = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.1"
    scenario = sys.argv[2] if len(sys.argv) > 2 else "internal_network"
    
    scanner = HybridScanningStrategy(target)
    strategy = scanner.select_strategy(scenario)
    strategy()

```
---

<a id="-casos-de-uso-específicos-por-herramienta"></a>
## 🎯 Casos de Uso Específicos por Herramienta

### Matriz de Decisión: ¿Qué Herramienta Usar?

```
#!/bin/bash
# tool-selection-matrix.sh

echo "🔧 MATRIZ DE SELECCIÓN DE HERRAMIENTAS"
echo ""

check_scenario() {
    local scenario="$1"
    local requirements=("${@:2}")
    
    echo "ESCENARIO: $scenario"
    echo "REQUISIOS: ${requirements[*]}"
    
    if [[ " ${requirements[*]} " =~ " velocidad " ]] && [[ " ${requirements[*]} " =~ " facilidad " ]]; then
        echo "HERRAMIENTA: RustScan"
        echo "COMANDO: rustscan -a TARGET -- -sC -sV"
    elif [[ " ${requirements[*]} " =~ " internet-scale " ]] || [[ " ${requirements[*]} " =~ " maxima-velocidad " ]]; then
        echo "HERRAMIENTA: Masscan"
        echo "COMANDO: masscan -p1-1000 TARGET --rate 10000"
    elif [[ " ${requirements[*]} " =~ " completo " ]] || [[ " ${requirements[*]} " =~ " udp " ]]; then
        echo "HERRAMIENTA: Nmap"
        echo "COMANDO: nmap -sS -sU -O -A TARGET"
    elif [[ " ${requirements[*]} " =~ " estudio-investigacion " ]]; then
        echo "HERRAMIENTA: Zmap"
        echo "COMANDO: zmap -p 443 -o resultados.txt"
    else
        echo "HERRAMIENTA: Combinación"
        echo "ESTRATEGIA: RustScan + Nmap"
    fi
    echo ""
}

# Ejemplos de escenarios
check_scenario "Pentesting interno" "velocidad" "facilidad" "automatización"
check_scenario "Auditoría de compliance" "completo" "documentación" "reporting"
check_scenario "Estudio de seguridad internet" "internet-scale" "maxima-velocidad"
check_scenario "Respuesta a incidentes" "velocidad" "rapido" "critico"
check_scenario "CTF/Hacking competition" "velocidad" "facilidad" "automático"
check_scenario "Investigación académica" "estudio-investigacion" "escala" "precisión"

```

---

<a id="-migración-desde-otras-herramientas"></a>
## 🔄 Migración desde Otras Herramientas

### De Nmap a RustScan: Comandos Equivalentes
```
#!/bin/bash
# nmap-to-rustscan-migration.sh

echo "GUÍA DE MIGRACIÓN: NMAP → RUSTSCAN"

# 1. Escaneo básico de puertos
echo "1. Escaneo básico:"
echo "   NMAP: nmap -sS 192.168.1.1"
echo "   RUSTSCAN: rustscan -a 192.168.1.1"
echo ""

# 2. Escaneo con detección de versión
echo "2. Escaneo con detección de servicio:"
echo "   NMAP: nmap -sV 192.168.1.1"
echo "   RUSTSCAN: rustscan -a 192.168.1.1 -- -sV"
echo ""

# 3. Escaneo de rango de red
echo "3. Escaneo de red:"
echo "   NMAP: nmap -sS 192.168.1.0/24"
echo "   RUSTSCAN: rustscan -a 192.168.1.0/24"
echo ""

# 4. Escaneo con scripts
echo "4. Escaneo con scripts:"
echo "   NMAP: nmap --script default 192.168.1.1"
echo "   RUSTSCAN: rustscan -a 192.168.1.1 -- -sC"
echo ""

# 5. Escaneo completo
echo "5. Escaneo completo:"
echo "   NMAP: nmap -A 192.168.1.1"
echo "   RUSTSCAN: rustscan -a 192.168.1.1 -- -A"
echo ""

# 6. COMANDOS NO DIRECTAMENTE EQUIVALENTES
echo "COMANDOS SIN EQUIVALENTE DIRECTO:"
echo "   • Escaneo UDP: nmap -sU (No soportado en RustScan)"
echo "   • OS Detection: nmap -O (Limitado en RustScan)"
echo "   • Técnicas avanzadas: nmap -D (Decoy) etc."
```

### Script de Adaptación Automática

python

#!/usr/bin/env python3
# nmap-command-adapter.py

import re
import sys

class NmapToRustScanAdapter:
    def __init__(self):
        self.mapping = {
            r'-sS\s': '',  # SYN scan es el default en RustScan
            r'-sT\s': '',  # Connect scan también soportado
            r'-p-': '',    # Todos los puertos es el default
            r'-p\s+(\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*)': r'-p \1',
            r'--script\s+(\S+)': r'-- --script \1',
            r'-sV': r'-- -sV',
            r'-sC': r'-- -sC',
            r'-A': r'-- -A',
            r'-O': r'-- -O',
        }
        
        self.unsupported = [
            r'-sU',  # UDP scan
            r'-sA',  # ACK scan  
            r'-sW',  # Window scan
            r'-sM',  # Maimon scan
            r'-sN',  # Null scan
            r'-sF',  # FIN scan
            r'-sX',  # Xmas scan
            r'-D',   # Decoy
            r'-S',   # Spoof source
            r'-e',   # Interface
            r'--source-port',
            r'--data-length',
            r'--ttl',
            r'--spoof-mac',
        ]
    
    def adapt_command(self, nmap_command):
        """Adaptar comando de Nmap a RustScan"""
        original_cmd = nmap_command
        rustscan_cmd = nmap_command
        
        # Remover argumentos no soportados
        for unsupported_arg in self.unsupported:
            rustscan_cmd = re.sub(unsupported_arg + r'\s+\S+', '', rustscan_cmd)
            rustscan_cmd = re.sub(unsupported_arg, '', rustscan_cmd)
        
        # Aplicar mapeo de argumentos
        for pattern, replacement in self.mapping.items():
            rustscan_cmd = re.sub(pattern, replacement, rustscan_cmd)
        
        # Asegurar que el target esté en el formato correcto
        rustscan_cmd = re.sub(r'nmap\s+', 'rustscan -a ', rustscan_cmd)
        
        # Limpiar espacios extra
        rustscan_cmd = ' '.join(rustscan_cmd.split())
        
        return rustscan_cmd
    
    def check_unsupported_features(self, nmap_command):
        """Verificar características no soportadas"""
        unsupported_found = []
        
        for feature in self.unsupported:
            if re.search(feature, nmap_command):
                unsupported_found.append(feature)
        
        return unsupported_found

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 nmap-command-adapter.py 'nmap command'")
        sys.exit(1)
    
    nmap_cmd = ' '.join(sys.argv[1:])
    adapter = NmapToRustScanAdapter()
    
    print("ADAPTANDO COMANDO NMAP A RUSTSCAN")
    print(f"Comando original: {nmap_cmd}")
    
    # Verificar características no soportadas
    unsupported = adapter.check_unsupported_features(nmap_cmd)
    if unsupported:
        print("Características no soportadas en RustScan:")
        for feature in unsupported:
            print(f"   - {feature}")
        print("   Estas características serán omitidas.")
    
    # Adaptar comando
    rustscan_cmd = adapter.adapt_command(nmap_cmd)
    print(f"Comando adaptado: {rustscan_cmd}")
    
    # Mostrar advertencias adicionales
    if '-sU' in nmap_cmd:
        print("\nIMPORTANTE: RustScan no soporta escaneo UDP.")
        print("   Para escaneo UDP, necesitarás usar Nmap directamente:")
        print(f"   nmap {nmap_cmd}")

---

### Cómo Contribuir al Desarrollo

**🤝 CÓMO CONTRIBUIR AL DESARROLLO DE RUSTSCAN**

**1. 📚 REPORTAR BUGS Y SUGERIR MEJORAS**:
- GitHub Issues: https://github.com/RustScan/RustScan/issues"
- Incluir version, sistema operativo, comando ejecutado"
- Proporcionar logs y output de error"


**2. 🔧 CONTRIBUIR CÓDIGO:**
- Fork el repositorio en GitHub
- Crear una rama para tu feature"
- Seguir las convenciones de código Rust"
- Incluir tests para nuevas funcionalidades"
  
**3 📖 MEJORAR DOCUMENTACIÓN:**
- Actualizar el README.md"
- Agregar ejemplos de uso"
- Traducir documentación"


**4 🧪 PROBAR VERSIONES DE DESARROLLO:**
```
git clone https://github.com/RustScan/RustScan.git"
cd RustScan"
cargo build --release"
 ./target/release/rustscan --help"
```

**5 🐛 PROPORCIONAR FEEDBACK:**
- Probar en diferentes entornos
- Reportar problemas de performance
- Sugerir mejoras de usabilidad"

---
