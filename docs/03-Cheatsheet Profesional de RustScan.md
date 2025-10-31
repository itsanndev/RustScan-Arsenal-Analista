
## 🎯 Índice
1. [Comandos Esenciales](#comandos-esenciales)
2. [Escaneos Avanzados](#escaneos-avanzados)
3. [Técnicas de Evasión y Sigilo](#técnicas-de-evasión-y-sigilo)
4. [Integración con Nmap](#integración-con-nmap)
5. [Scripting y Automatización](#scripting-y-automatización)
6. [Configuración Persistente](#configuración-persistente)
7. [Combinación con Otras Herramientas](#combinación-con-otras-herramientas)
8. [Troubleshooting Rápido](#troubleshooting-rápido)
    

---

<a id="comandos-esenciales"></a>
## 🚀 Comandos Esenciales

### Escaneos Básicos
```
# Escaneo simple a una IP
rustscan -a 192.168.1.1

# Escaneo a rango de red completo
rustscan -a 192.168.1.0/24

# Escaneo a múltiples objetivos
rustscan -a 192.168.1.1,192.168.1.50-100

# Especificar puertos personalizados
rustscan -a 192.168.1.1 -p 80,443,22,21,53

# Escaneo desde archivo de hosts
rustscan -a hosts.txt

# Escaneo de puertos por rango
rustscan -a 192.168.1.1 --range 1-1000
```

### Opciones de Salida
```
# Salida greppeable (fácil para parsing)
rustscan -a 192.168.1.1 -g

# Modo verbose para debugging
rustscan -a 192.168.1.1 -v

# Muy verbose (máxima información)
rustscan -a 192.168.1.1 -vv

# Salida silenciosa (solo resultados)
rustscan -a 192.168.1.1 --quiet
```

### Gestión de Objetivos
```
# Escaneo de hostname/DNS
rustscan -a example.com

# Combinación de IPs y hostnames
rustscan -a 192.168.1.1,example.com,10.0.0.0/29

# Excluir hosts específicos
rustscan -a 192.168.1.0/24 --exclude 192.168.1.100,192.168.1.200
```

---

<a id="escaneos-avanzados"></a>
## ⚡ Escaneos Avanzados

### Optimización de Rendimiento

```
# Ajuste de batch size para máxima velocidad
rustscan -a 192.168.1.0/24 -b 15000

# Timeout personalizado por puerto
rustscan -a 192.168.1.1 --timeout 1000

# Número de hilos personalizado
rustscan -a 192.168.1.1 -t 5000

# Límite de tasa de paquetes
rustscan -a 192.168.1.1 --rate-limit 1000

```

### Orden de Escaneo

```
# Orden serial (predeterminado)
rustscan -a 192.168.1.1 --scan-order Serial

# Orden aleatorio (evasión básica)
rustscan -a 192.168.1.1 --scan-order Random

# Orden inverso
rustscan -a 192.168.1.1 --scan-order Reverse
```

### Escaneos Específicos

```
# Solo puertos más comunes (top ports)
rustscan -a 192.168.1.1 --top 1000

# Puertos personalizados por servicio
rustscan -a 192.168.1.1 -p 21,22,23,25,53,80,110,443,993,995,1433,3389,5432,5900,6379,27017

# Escaneo de rangos múltiples
rustscan -a 192.168.1.1 -p 1-100,1000-2000,8080-9090
```

---

<a id="técnicas-de-evasión-y-sigilo"></a>
## 🕵️ Técnicas de Evasión y Sigilo

### Timing y Velocidad Controlada
```
# Escaneo lento (evasión de IDS)
rustscan -a 192.168.1.1 --timeout 5000 -b 100

# Timing adaptativo automático
rustscan -a 192.168.1.1 --adaptive

# Delay entre paquetes
rustscan -a 192.168.1.1 --delay 100
```

### Técnicas de Ofuscación

```
# Orden aleatorio de puertos
rustscan -a 192.168.1.1 --scan-order Random --timeout 2000

# Source port personalizado (requiere priv.)
sudo rustscan -a 192.168.1.1 --source-port 53

# Fragmentación de paquetes
rustscan -a 192.168.1.1 --fragment
```

### Escaneos Sigilosos
```
# Escaneo con conexiones completas
rustscan -a 192.168.1.1 --connect-scan

# Modo sigiloso (SYN scan)
sudo rustscan -a 192.168.1.1 --syn-scan

# Evasión de reglas de firewall
rustscan -a 192.168.1.1 --scan-order Random --timeout 3000 -b 500
```

---

<a id="integración-con-nmap"></a>
## 🔗 Integración con Nmap

### Pipes Automáticos Básicos
```

# Pipe básico a Nmap
rustscan -a 192.168.1.1 -- -sC -sV

# Escaneo completo con Nmap
rustscan -a 192.168.1.1 -- -A -sC -sV -O

# Solo detección de servicios
rustscan -a 192.168.1.1 -- -sV

# Scripts de seguridad de Nmap
rustscan -a 192.168.1.1 -- --script vuln

# Múltiples scripts de Nmap
rustscan -a 192.168.1.1 -- --script "http-*,ssh-*"
```

### Configuraciones Avanzadas de Nmap
```

# Output formats de Nmap
rustscan -a 192.168.1.1 -- -oA scan_results

# Timing templates de Nmap
rustscan -a 192.168.1.1 -- -T4

# Escaneo UDP de puertos específicos
rustscan -a 192.168.1.1 -p 53,161 -- -sU -sV

# Fingerprinting avanzado
rustscan -a 192.168.1.1 -- -O --osscan-guess
```

### Optimización de Pipelines
```
# Solo puertos abiertos a Nmap (más eficiente)
rustscan -a 192.168.1.1 --greppable | grep open | cut -d'/' -f1 | tr '\n' ',' | xargs -I{} nmap -p{} -sC -sV 192.168.1.1

# Con detección de versión agresiva
rustscan -a 192.168.1.1 -- -sV --version-intensity 9

```
---

<a id="scripting-y-automatización"></a>
## 🤖 Scripting y Automatización

### RustScan Scripting Engine (RSE)

```
# Ejecutar scripts por defecto
rustscan -a 192.168.1.1 --scripts default

# Scripts personalizados
rustscan -a 192.168.1.1 --scripts custom

# Scripts específicos por tags
rustscan -a 192.168.1.1 --scripts "http,security"

# Deshabilitar scripts
rustscan -a 192.168.1.1 --scripts none
```

### Ejemplos de Scripts RSE
```
#!/usr/bin/python3
# tags = ["http", "security"]
# trigger_port = "80,443,8080,8443"
# call_format = "python3 {{script}} {{ip}} {{port}}"

import requests
import sys

def scan_http(ip, port):
    try:
        url = f"http://{ip}:{port}"
        response = requests.get(url, timeout=5, verify=False)
        print(f"[HTTP] {url} - Status: {response.status_code}")
        if 'Server' in response.headers:
            print(f"[HTTP] Server: {response.headers['Server']}")
    except Exception as e:
        print(f"[ERROR] {e}")

if __name__ == "__main__":
    if len(sys.argv) == 3:
        scan_http(sys.argv[1], sys.argv[2])
```

### Automatización con Bash
```
#!/bin/bash
# automated-scan.sh

TARGETS_FILE="targets.txt"
OUTPUT_DIR="scan_results_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTPUT_DIR"

echo "Iniciando escaneo automatizado..."

while IFS= read -r target; do
    echo "Escaneando: $target"
    
    # Fase 1: Descubrimiento rápido
    rustscan -a "$target" --timeout 2000 -b 5000 > "$OUTPUT_DIR/${target}_discovery.txt"
    
    # Fase 2: Análisis detallado de puertos abiertos
    open_ports=$(grep -E '^[0-9]+/open' "$OUTPUT_DIR/${target}_discovery.txt" | cut -d'/' -f1 | tr '\n' ',' | sed 's/,$//')
    
    if [ -n "$open_ports" ]; then
        echo "Puertos abiertos en $target: $open_ports"
        rustscan -a "$target" -p "$open_ports" -- -sC -sV -A -oA "$OUTPUT_DIR/${target}_detailed"
    else
        echo "No se encontraron puertos abiertos en $target"
    fi
    
done < "$TARGETS_FILE"

echo "ESCANEO FINALIZADO. Resultados en: $OUTPUT_DIR"
```

### Automatización con Python
```
#!/usr/bin/env python3
import subprocess
import json
import sys
from concurrent.futures import ThreadPoolExecutor

class RustScanAutomation:
    def __init__(self, targets):
        self.targets = targets
        self.results = {}
    
    def scan_target(self, target):
        """Escaneo individual de objetivo"""
        try:
            cmd = f"rustscan -a {target} --greppable"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            open_ports = []
            for line in result.stdout.split('\n'):
                if '/open/' in line:
                    port = line.split('/')[0]
                    open_ports.append(port)
            
            self.results[target] = {
                'open_ports': open_ports,
                'ports_count': len(open_ports)
            }
            
            return f"{target}: {len(open_ports)} puertos abiertos"
            
        except Exception as e:
            return f"{target}: Error - {e}"
    
    def run_parallel_scans(self, max_workers=5):
        """Escaneo paralelo de múltiples objetivos"""
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            results = list(executor.map(self.scan_target, self.targets))
        
        for result in results:
            print(result)
        
        return self.results

if __name__ == "__main__":
    targets = sys.argv[1:] if len(sys.argv) > 1 else ["192.168.1.1"]
    scanner = RustScanAutomation(targets)
    results = scanner.run_parallel_scans()
    
    # Guardar resultados en JSON
    with open('scan_results.json', 'w') as f:
        json.dump(results, f, indent=2)

```
---

<a id="configuración-persistente"></a>
## ⚙️ Configuración Persistente

### Archivo de Configuración Global
```
# ~/.rustscan.toml
# Configuración persistente de RustScan

[scan]
# Tamaño del batch para escaneos
batch_size = 10000

# Timeout por puerto en milisegundos
timeout = 2000

# Orden de escaneo predeterminado
scan_order = "Serial"

# Timeout específico para TCP
tcp_port_timeout = 1000

# Salida greppeable por defecto
greppable = false

[scripts]
# Script predeterminado a ejecutar
default_script = "nmap"

# Timeout para scripts en segundos
script_timeout = 30

[performance]
# Límite de archivos del sistema
ulimit = 65535

# Habilitar aprendizaje adaptativo
adaptive_learning = true
```

### Variables de Entorno
```
# Configurar en ~/.bashrc o ~/.zshrc

# Batch size por defecto
export RUSTSCAN_BATCH_SIZE=5000

# Timeout global
export RUSTSCAN_TIMEOUT=1500

# Orden de escaneo
export RUSTSCAN_SCAN_ORDER="Random"

# Salida greppeable
export RUSTSCAN_GREPPABLE=true

# Recargar configuración
source ~/.bashrc
```

### Configuración RSE Avanzada
```
# ~/.rustscan_scripts.toml
# Configuración del motor de scripting

[scripts]
tags = ["http", "security", "scanning"]
ports = ["80", "443", "8080", "8443"]
developer = ["security-team"]
call_format = "python3 {{script}} {{ip}} {{port}}"

[[custom_scripts]]
name = "http-scanner"
path = "~/scripts/http-scanner.py"
tags = ["http", "web"]
trigger_ports = ["80", "443", "8080", "8443"]

[[custom_scripts]]
name = "ssh-audit"
path = "~/scripts/ssh-audit.sh"
tags = ["security", "ssh"]
trigger_ports = ["22"]
```

---

<a id="combinación-con-otras-herramientas"></a>
## 🔗 Combinación con Otras Herramientas

### RustScan + Nuclei
```
# Descubrimiento rápido + escaneo de vulnerabilidades
rustscan -a 192.168.1.1 -p 80,443,8080,8443 | grep open | cut -d'/' -f1 | \
xargs -I{} echo "http://192.168.1.1:{}" | nuclei -t /path/to/templates

# Con detección automática de servicios web
rustscan -a 192.168.1.0/24 --scripts http | grep 'http://' | nuclei -t vulnerabilities/
```

### RustScan + GoBuster
```
# Descubrimiento + directory busting
rustscan -a 192.168.1.1 -p 80,443,8080,8443 | grep open | \
awk -F'/' '{print "http://192.168.1.1:"$1}' | xargs -I{} gobuster dir -u {} -w common.txt
```

### RustScan + WhatWeb
```
# Fingerprinting automático de tecnologías web
rustscan -a 192.168.1.1 -p 80,443,8080,8443 | grep open | \
awk -F'/' '{print "http://192.168.1.1:"$1}' | whatweb -i-
```

### RustScan + Metasploit
```
# Integración con Metasploit para escaneo de servicios
rustscan -a 192.168.1.1 --greppable | grep open | cut -d'/' -f1 | \
xargs -I{} echo "use auxiliary/scanner/portscan/tcp; set RHOSTS 192.168.1.1; set PORTS {}; run" | msfconsole

```
### Pipeline Completo de Análisis
```
#!/bin/bash
# complete-analysis.sh

TARGET=$1
OUTPUT_DIR="analysis_${TARGET}_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTPUT_DIR"

echo "Iniciando análisis completo de $TARGET"

# Fase 1: Descubrimiento con RustScan
echo "Fase 1: Descubrimiento de puertos..."
rustscan -a "$TARGET" --timeout 2000 -b 8000 > "$OUTPUT_DIR/ports.txt"

# Fase 2: Análisis Nmap
echo "Fase 2: Análisis de servicios..."
open_ports=$(grep -E '^[0-9]+/open' "$OUTPUT_DIR/ports.txt" | cut -d'/' -f1 | tr '\n' ',' | sed 's/,$//')
rustscan -a "$TARGET" -p "$open_ports" -- -sC -sV -A -oA "$OUTPUT_DIR/nmap_scan"

# Fase 3: Análisis web si hay puertos HTTP/HTTPS
if echo "$open_ports" | grep -qE '(80|443|8080|8443)'; then
    echo "Fase 3: Análisis web..."
    echo "$open_ports" | tr ',' '\n' | grep -E '^(80|443|8080|8443)$' | \
    xargs -I{} sh -c 'whatweb "http://$1:{}" 2>/dev/null' _ "$TARGET" > "$OUTPUT_DIR/whatweb.txt"
fi

echo "Análisis completado: $OUTPUT_DIR"
```

---

<a id="troubleshooting-rápido"></a>
## 🚨 Troubleshooting Rápido
### Problemas Comunes y Soluciones Inmediatas
```
# Error: "Too many open files"
ulimit -n 65535
# O permanente: echo 'fs.file-max = 1000000' | sudo tee -a /etc/sysctl.conf

# Error: "Connection reset by peer"
rustscan -a 192.168.1.1 -b 1000 --timeout 3000

# Nmap no encontrado
sudo apt install nmap  # Debian/Ubuntu
brew install nmap     # macOS

# Escaneo muy lento
rustscan -a 192.168.1.1 -b 15000 --timeout 500

# Permisos insuficientes para SYN scan
sudo rustscan -a 192.168.1.1 -- -sS
```

### Comandos de Diagnóstico
```
# Verificar configuración actual
rustscan --help | grep -A5 -B5 "batch\|timeout"

# Verificar límites del sistema
ulimit -a

# Test de conectividad básica
rustscan -a 127.0.0.1 -p 22,80,443 --greppable

# Verificar instalación de dependencias
which nmap && nmap --version
which rustscan && rustscan --version
```

### Optimización para Entornos Específicos
```
# Para redes lentas o con alta latencia
rustscan -a 192.168.1.1 --timeout 5000 -b 500

# Para redes locales rápidas
rustscan -a 192.168.1.1 --timeout 500 -b 20000

# Para escaneos sigilosos
rustscan -a 192.168.1.1 --scan-order Random --timeout 2000 -b 1000

# Para máxima velocidad (riesgo de pérdida de paquetes)
rustscan -a 192.168.1.1 --timeout 200 -b 25000
```
