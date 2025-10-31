#!/bin/bash
#
# RustScan Compliance Audit Script
# Realiza auditorías de compliance automatizadas usando RustScan
# Compatible con estándares CIS, NIST, y frameworks de seguridad
#

set -euo pipefail

# Configuración
TARGETS_FILE="${1:-targets.txt}"
COMPLIANCE_STANDARD="${2:-cis}"
OUTPUT_DIR="compliance_audit_$(date +%Y%m%d_%H%M%S)"
LOG_FILE="$OUTPUT_DIR/audit.log"

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Función de logging
log() {
    local level=$1
    shift
    local message=$*
    local timestamp=$(date +'%Y-%m-%d %H:%M:%S')
    
    case $level in
        "INFO") color=$BLUE ;;
        "SUCCESS") color=$GREEN ;;
        "WARNING") color=$YELLOW ;;
        "ERROR") color=$RED ;;
        *) color=$NC ;;
    esac
    
    echo -e "${color}[$timestamp] $level: $message${NC}" | tee -a "$LOG_FILE"
}

# Verificación de prerrequisitos
check_prerequisites() {
    log "INFO" "Verificando prerrequisitos del sistema..."
    
    if ! command -v rustscan &> /dev/null; then
        log "ERROR" "RustScan no encontrado. Instalar con: sudo apt install rustscan"
        exit 1
    fi
    
    if ! command -v nmap &> /dev/null; then
        log "ERROR" "Nmap no encontrado. Instalar con: sudo apt install nmap"
        exit 1
    fi
    
    if [ ! -f "$TARGETS_FILE" ]; then
        log "ERROR" "Archivo de targets no encontrado: $TARGETS_FILE"
        exit 1
    fi
    
    log "SUCCESS" "Prerrequisitos verificados correctamente"
}

# Configuración de estándares de compliance
setup_compliance_checks() {
    log "INFO" "Configurando checks para estándar: $COMPLIANCE_STANDARD"
    
    case $COMPLIANCE_STANDARD in
        "cis")
            RISKY_PORTS="23 135 139 445 3389 1433 5432 1521"
            REQUIRED_PORTS="22 80 443"
            MAX_OPEN_PORTS=50
            ;;
        "nist")
            RISKY_PORTS="21 23 25 135 139 445 1433 3389"
            REQUIRED_PORTS="22 80 443 53"
            MAX_OPEN_PORTS=100
            ;;
        "pci")
            RISKY_PORTS="21 23 135 139 445 1433 3389 5432"
            REQUIRED_PORTS="443 22"
            MAX_OPEN_PORTS=30
            ;;
        *)
            log "WARNING" "Estándar no reconocido. Usando configuración base."
            RISKY_PORTS="21 23 135 139 445 3389"
            REQUIRED_PORTS="22 80 443"
            MAX_OPEN_PORTS=50
            ;;
    esac
    
    log "SUCCESS" "Configuración de compliance cargada"
}

# Fase 1: Descubrimiento de activos
discovery_phase() {
    log "INFO" "Iniciando fase de descubrimiento de activos"
    
    mkdir -p "$OUTPUT_DIR"
    
    # Escaneo rápido con RustScan
    log "INFO" "Ejecutando escaneo de descubrimiento con RustScan..."
    rustscan -a "-" --timeout 2000 -b 10000 --greppable < "$TARGETS_FILE" > "$OUTPUT_DIR/01_discovery_raw.txt"
    
    # Procesar resultados
    grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' "$OUTPUT_DIR/01_discovery_raw.txt" | sort -u > "$OUTPUT_DIR/02_live_hosts.txt"
    
    local host_count=$(wc -l < "$OUTPUT_DIR/02_live_hosts.txt")
    log "SUCCESS" "Hosts activos identificados: $host_count"
    
    echo "$host_count"
}

# Fase 2: Evaluación de servicios
service_assessment_phase() {
    local host_count=$1
    
    log "INFO" "Iniciando evaluación de servicios"
    
    # Escaneo de servicios por host
    while IFS= read -r host; do
        log "INFO" "Evaluando servicios en: $host"
        
        # RustScan + Nmap para análisis detallado
        rustscan -a "$host" --timeout 1500 -- -sC -sV -O --script safe -oA "$OUTPUT_DIR/03_services_$host" &
        
        # Control de concurrencia
        local background_jobs=$(jobs -rp | wc -l)
        while [ "$background_jobs" -ge 5 ]; do
            sleep 2
            background_jobs=$(jobs -rp | wc -l)
        done
        
    done < "$OUTPUT_DIR/02_live_hosts.txt"
    
    wait
    log "SUCCESS" "Evaluación de servicios completada"
}

# Fase 3: Análisis de compliance
compliance_analysis_phase() {
    log "INFO" "Realizando análisis de compliance"
    
    local compliance_violations=0
    local compliance_warnings=0
    
    # Analizar cada host
    while IFS= read -r host; do
        log "INFO" "Analizando compliance para: $host"
        
        local host_violations=0
        local host_warnings=0
        
        # Verificar puertos riesgosos
        if [ -f "$OUTPUT_DIR/03_services_${host}.nmap" ]; then
            for port in $RISKY_PORTS; do
                if grep -q "$port/open" "$OUTPUT_DIR/03_services_${host}.nmap"; then
                    log "WARNING" "VIOLACION: Puerto riesgoso $port abierto en $host"
                    echo "VIOLACION: Puerto $port - Servicio riesgoso detectado" >> "$OUTPUT_DIR/04_violations_${host}.txt"
                    ((host_violations++))
                fi
            done
            
            # Verificar puertos requeridos
            for port in $REQUIRED_PORTS; do
                if ! grep -q "$port/open" "$OUTPUT_DIR/03_services_${host}.nmap"; then
                    log "WARNING" "ADVERTENCIA: Puerto requerido $port cerrado en $host"
                    echo "ADVERTENCIA: Puerto $port - Servicio requerido no disponible" >> "$OUTPUT_DIR/04_violations_${host}.txt"
                    ((host_warnings++))
                fi
            done
            
            # Verificar número de puertos abiertos
            local open_ports_count=$(grep -c "open" "$OUTPUT_DIR/03_services_${host}.nmap" || true)
            if [ "$open_ports_count" -gt "$MAX_OPEN_PORTS" ]; then
                log "WARNING" "ADVERTENCIA: Demasiados puertos abiertos ($open_ports_count) en $host"
                echo "ADVERTENCIA: $open_ports_count puertos abiertos - Excede el limite de $MAX_OPEN_PORTS" >> "$OUTPUT_DIR/04_violations_${host}.txt"
                ((host_warnings++))
            fi
            
            # Verificar servicios con versiones obsoletas
            if grep -q -E "Apache/2\.2|nginx/1\.[0-6]|OpenSSH_5|OpenSSH_6" "$OUTPUT_DIR/03_services_${host}.nmap"; then
                log "WARNING" "ADVERTENCIA: Servicios obsoletos detectados en $host"
                echo "ADVERTENCIA: Servicios con versiones potencialmente obsoletas" >> "$OUTPUT_DIR/04_violations_${host}.txt"
                ((host_warnings++))
            fi
        fi
        
        ((compliance_violations += host_violations))
        ((compliance_warnings += host_warnings))
        
    done < "$OUTPUT_DIR/02_live_hosts.txt"
    
    echo "$compliance_violations:$compliance_warnings"
}

# Fase 4: Generación de reportes
reporting_phase() {
    local violations=$1
    local warnings=$2
    
    log "INFO" "Generando reportes de compliance"
    
    # Reporte ejecutivo
    {
        echo "REPORTE DE COMPLIANCE - $COMPLIANCE_STANDARD"
        echo "============================================"
        echo "Fecha: $(date)"
        echo "Estándar: $COMPLIANCE_STANDARD"
        echo "Targets evaluados: $(wc -l < "$TARGETS_FILE")"
        echo "Hosts activos: $(wc -l < "$OUTPUT_DIR/02_live_hosts.txt")"
        echo ""
        echo "RESUMEN DE CUMPLIMIENTO:"
        echo "- Violaciones criticas: $violations"
        echo "- Advertencias: $warnings"
        echo "- Estado: $([ $violations -eq 0 ] && echo "CUMPLE" || echo "NO CUMPLE")"
        echo ""
        echo "CONFIGURACION APLICADA:"
        echo "- Puertos riesgosos: $RISKY_PORTS"
        echo "- Puertos requeridos: $REQUIRED_PORTS"
        echo "- Maximo puertos abiertos: $MAX_OPEN_PORTS"
        echo ""
        echo "HOSTS EVALUADOS:"
        cat "$OUTPUT_DIR/02_live_hosts.txt"
        echo ""
        echo "VIOLACIONES DETECTADAS:"
        find "$OUTPUT_DIR" -name "04_violations_*.txt" -exec cat {} \; 2>/dev/null || echo "No se encontraron violaciones"
    } > "$OUTPUT_DIR/05_compliance_report.txt"
    
    # Reporte técnico detallado
    {
        echo "REPORTE TECNICO DETALLADO"
        echo "========================="
        echo ""
        echo "RESULTADOS POR HOST:"
        echo ""
        
        while IFS= read -r host; do
            echo "HOST: $host"
            echo "----------------"
            if [ -f "$OUTPUT_DIR/03_services_${host}.nmap" ]; then
                grep "open" "$OUTPUT_DIR/03_services_${host}.nmap" | head -10
            fi
            echo ""
        done < "$OUTPUT_DIR/02_live_hosts.txt"
    } > "$OUTPUT_DIR/06_technical_report.txt"
    
    log "SUCCESS" "Reportes generados en: $OUTPUT_DIR"
}

# Función principal
main() {
    log "INFO" "Iniciando auditoria de compliance"
    log "INFO" "Targets: $TARGETS_FILE"
    log "INFO" "Estándar: $COMPLIANCE_STANDARD"
    
    # Verificar prerrequisitos
    check_prerequisites
    
    # Configurar estándar de compliance
    setup_compliance_checks
    
    # Ejecutar fases de auditoría
    local host_count=$(discovery_phase)
    
    if [ "$host_count" -eq 0 ]; then
        log "WARNING" "No se encontraron hosts activos. Finalizando auditoría."
        exit 0
    fi
    
    service_assessment_phase "$host_count"
    
    local compliance_results=$(compliance_analysis_phase)
    local violations=$(echo "$compliance_results" | cut -d: -f1)
    local warnings=$(echo "$compliance_results" | cut -d: -f2)
    
    reporting_phase "$violations" "$warnings"
    
    # Resultado final
    log "INFO" "========================================"
    log "INFO" "AUDITORIA COMPLETADA"
    log "INFO" "Violaciones: $violations"
    log "INFO" "Advertencias: $warnings"
    
    if [ "$violations" -eq 0 ]; then
        log "SUCCESS" "ESTADO: CUMPLIMIENTO SATISFACTORIO"
    else
        log "ERROR" "ESTADO: NO CUMPLE - Requiere accion correctiva"
    fi
    
    log "INFO" "Reportes guardados en: $OUTPUT_DIR"
}

# Manejo de señales
trap 'log "ERROR" "Auditoria interrumpida por el usuario"; exit 1' INT TERM

# Ejecución principal
if [ $# -eq 0 ]; then
    echo "Uso: $0 <targets_file> [compliance_standard]"
    echo "Estándares disponibles: cis, nist, pci"
    echo "Ejemplo: $0 targets.txt cis"
    exit 1
fi

main "$@"