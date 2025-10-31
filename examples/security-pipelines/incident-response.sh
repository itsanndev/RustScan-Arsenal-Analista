#!/bin/bash
#
# RustScan Incident Response Script
# Respuesta automatizada a incidentes de seguridad usando RustScan
# para evaluación rápida de compromisos potenciales
#

set -euo pipefail

# Configuración
INCIDENT_NETWORK="${1:-192.168.1.0/24}"
INCIDENT_TYPE="${2:-unknown}"
RESPONSE_DIR="incident_response_$(date +%Y%m%d_%H%M%S)"
LOG_FILE="$RESPONSE_DIR/incident_response.log"

# Configuración por tipo de incidente
case $INCIDENT_TYPE in
    "malware")
        SCAN_PRIORITY="suspicious_ports"
        RUSTSCAN_OPTS="--timeout 1000 -b 10000"
        ;;
    "ransomware")
        SCAN_PRIORITY="critical_services" 
        RUSTSCAN_OPTS="--timeout 1500 -b 15000"
        ;;
    "lateral_movement")
        SCAN_PRIORITY="network_services"
        RUSTSCAN_OPTS="--timeout 2000 -b 20000"
        ;;
    "unknown")
        SCAN_PRIORITY="comprehensive"
        RUSTSCAN_OPTS="--timeout 1500 -b 15000"
        ;;
    *)
        echo "Tipo de incidente no reconocido: $INCIDENT_TYPE"
        echo "Tipos: malware, ransomware, lateral_movement, unknown"
        exit 1
        ;;
esac

# Función de logging
log() {
    local level=$1
    shift
    local message=$*
    local timestamp=$(date +'%Y-%m-%d %H:%M:%S')
    
    echo "[$timestamp] $level: $message" | tee -a "$LOG_FILE"
}

# Inicialización
initialize_response() {
    log "INFO" "=== INCIDENT RESPONSE INITIALIZATION ==="
    log "INFO" "Incident Type: $INCIDENT_TYPE"
    log "INFO" "Network: $INCIDENT_NETWORK"
    log "INFO" "Response ID: $(basename "$RESPONSE_DIR")"
    
    mkdir -p "$RESPONSE_DIR"
    
    # Crear estructura de directorios
    mkdir -p "$RESPONSE_DIR/scan_results"
    mkdir -p "$RESPONSE_DIR/evidence"
    mkdir -p "$RESPONSE_DIR/reports"
    
    log "SUCCESS" "Incident response environment initialized"
}

# Fase 1: Evaluación rápida de la red
rapid_assessment_phase() {
    log "INFO" "=== FASE 1: EVALUACION RAPIDA DE RED ==="
    
    # Escaneo rápido con RustScan
    log "INFO" "Ejecutando escaneo rapido de red..."
    rustscan -a "$INCIDENT_NETWORK" $RUSTSCAN_OPTS --greppable > "$RESPONSE_DIR/01_rapid_scan.txt"
    
    # Identificar hosts activos
    grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' "$RESPONSE_DIR/01_rap