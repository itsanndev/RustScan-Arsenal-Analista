#!/bin/bash
#
# RustScan Complete Security Pipeline
# Pipeline integral de seguridad que combina múltiples herramientas
# con RustScan como núcleo de descubrimiento
#

set -euo pipefail

# Configuración
TARGET="${1:-192.168.1.0/24}"
MODE="${2:-comprehensive}"
OUTPUT_DIR="security_pipeline_$(date +%Y%m%d_%H%M%S)"
LOG_FILE="$OUTPUT_DIR/pipeline.log"

# Configuración por modo
case $MODE in
    "quick")
        RUSTSCAN_OPTS="--timeout 1000 -b 20000"
        SCAN_DEPTH="basic"
        ;;
    "comprehensive")
        RUSTSCAN_OPTS="--timeout 2000 -b 15000"
        SCAN_DEPTH="full"
        ;;
    "stealth")
        RUSTSCAN_OPTS="--timeout 3000 -b 5000 --scan-order Random"
        SCAN_DEPTH="basic"
        ;;
    *)
        echo "Modo no reconocido: $MODE"
        echo "Modos disponibles: quick, comprehensive, stealth"
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

# Verificación de herramientas
check_tools() {
    log "INFO" "Verificando herramientas disponibles..."
    
    local tools=("rustscan" "nmap" "curl")
    local missing_tools=()
    
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
            log "WARNING" "Herramienta no disponible: $tool"
        else
            log "INFO" "Herramienta disponible: $tool"
        fi
    done
    
    if [ ${#missing_tools[@]} -gt 0 ]; then
        log "WARNING" "Herramientas faltantes: ${missing_tools[*]}"
    fi
}

# Fase 1: Descubrimiento de activos
discovery_phase() {
    log "INFO" "=== FASE 1: DESCUBRIMIENTO DE ACTIVOS ==="
    
    mkdir -p "$OUTPUT_DIR"
    
    log "INFO" "Ejecutando descubrimiento con RustScan..."
    rustscan -a "$TARGET" $RUSTSCAN_OPTS --greppable > "$OUTPUT_DIR/01_discovery.txt"
    
    # Extraer hosts activos
    grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' "$OUTPUT_DIR/01_discovery.txt" | sort -u > "$OUTPUT_DIR/02_live_hosts.txt"
    
    local host_count
    host_count=$(wc -l < "$OUTPUT_DIR/02_live_hosts.txt")
    log "SUCCESS" "Hosts activos descubiertos: $host_count"
    
    # Mostrar hosts
    if [ "$host_count" -gt 0 ]; then
        log "INFO" "Hosts descubiertos:"
        while IFS= read -r host; do
            log "INFO" "  - $host"
        done < "$OUTPUT_DIR/02_live_hosts.txt"
    fi
    
    echo "$host_count"
}

# Fase 2: Análisis de servicios
service_analysis_phase() {
    local host_count=$1
    
    log "INFO" "=== FASE 2: ANALISIS DE SERVICIOS ==="
    
    if [ "$host_count" -eq 0 ]; then
        log "WARNING" "No hay hosts para analizar"
        return
    fi
    
    mkdir -p "$OUTPUT_DIR/services"
    
    # Análisis por host
    while IFS= read -r host; do
        log "INFO" "Analizando servicios en: $host"
        
        # RustScan + Nmap integrado
        rustscan -a "$host" $RUSTSCAN_OPTS -- -sC -sV -O -A -oA "$OUTPUT_DIR/services/analysis_$host" &
        
        # Control de concurrencia
        local jobs_count
        jobs_count=$(jobs -rp | wc -l)
        while [ "$jobs_count" -ge 3 ]; do
            sleep 2
            jobs_count=$(jobs -rp | wc -l)
        done
        
    done < "$OUTPUT_DIR/02_live_hosts.txt"
    
    wait
    log "SUCCESS" "Analisis de servicios completado"
}

# Fase 3: Evaluación de seguridad
security_assessment_phase() {
    log "INFO" "=== FASE 3: EVALUACION DE SEGURIDAD ==="
    
    # Identificar servicios por categoría
    categorize_services
    perform_security_checks
    
    log "SUCCESS" "Evaluacion de seguridad completada"
}

# Categorizar servicios
categorize_services() {
    log "INFO" "Categorizando servicios descubiertos..."
    
    > "$OUTPUT_DIR/03_web_services.txt"
    > "$OUTPUT_DIR/03_critical_services.txt"
    > "$OUTPUT_DIR/03_risky_services.txt"
    
    while IFS= read -r host; do
        local nmap_file="$OUTPUT_DIR/services/analysis_${host}.nmap"
        
        if [ ! -f "$nmap_file" ]; then
            continue
        fi
        
        # Servicios web
        if grep -q "80/open\|443/open\|8080/open\|8443/open" "$nmap_file"; then
            echo "$host" >> "$OUTPUT_DIR/03_web_services.txt"
        fi
        
        # Servicios críticos
        if grep -q "22/open\|3389/open\|1433/open\|5432/open" "$nmap_file"; then
            echo "$host" >> "$OUTPUT_DIR/03_critical_services.txt"
        fi
        
        # Servicios riesgosos
        if grep -q "21/open\|23/open\|135/open\|139/open\|445/open" "$nmap_file"; then
            echo "$host" >> "$OUTPUT_DIR/03_risky_services.txt"
        fi
        
    done < "$OUTPUT_DIR/02_live_hosts.txt"
    
    local web_count critical_count risky_count
    web_count=$(wc -l < "$OUTPUT_DIR/03_web_services.txt" 2>/dev/null || echo 0)
    critical_count=$(wc -l < "$OUTPUT_DIR/03_critical_services.txt" 2>/dev/null || echo 0)
    risky_count=$(wc -l < "$OUTPUT_DIR/03_risky_services.txt" 2>/dev/null || echo 0)
    
    log "INFO" "Servicios categorizados:"
    log "INFO" "  - Web: $web_count"
    log "INFO" "  - Criticos: $critical_count"
    log "INFO" "  - Riesgosos: $risky_count"
}

# Realizar verificaciones de seguridad
perform_security_checks() {
    log "INFO" "Realizando verificaciones de seguridad..."
    
    # Verificar servicios riesgosos
    if [ -s "$OUTPUT_DIR/03_risky_services.txt" ]; then
        log "WARNING" "Servicios potencialmente riesgosos detectados:"
        while IFS= read -r host; do
            log "WARNING" "  - $host"
        done < "$OUTPUT_DIR/03_risky_services.txt"
    fi
    
    # Verificar versiones obsoletas
    check_obsolete_versions
    
    # Verificar configuraciones inseguras
    check_insecure_configurations
}

# Verificar versiones obsoletas
check_obsolete_versions() {
    log "INFO" "Verificando versiones obsoletas..."
    
    while IFS= read -r host; do
        local nmap_file="$OUTPUT_DIR/services/analysis_${host}.nmap"
        
        if [ ! -f "$nmap_file" ]; then
            continue
        fi
        
        # Buscar versiones específicas obsoletas
        if grep -q -E "Apache/2\.2|nginx/1\.[0-6]|OpenSSH_5|OpenSSH_6" "$nmap_file"; then
            log "WARNING" "Versiones obsoletas detectadas en $host"
            echo "HOST: $host" >> "$OUTPUT_DIR/04_obsolete_versions.txt"
            grep -E "Apache/2\.2|nginx/1\.[0-6]|OpenSSH_5|OpenSSH_6" "$nmap_file" >> "$OUTPUT_DIR/04_obsolete_versions.txt"
            echo "" >> "$OUTPUT_DIR/04_obsolete_versions.txt"
        fi
        
    done < "$OUTPUT_DIR/02_live_hosts.txt"
}

# Verificar configuraciones inseguras
check_insecure_configurations() {
    log "INFO" "Verificando configuraciones inseguras..."
    
    > "$OUTPUT_DIR/05_insecure_configs.txt"
    
    while IFS= read -r host; do
        local nmap_file="$OUTPUT_DIR/services/analysis_${host}.nmap"
        
        if [ ! -f "$nmap_file" ]; then
            continue
        fi
        
        # Buscar configuraciones específicas
        if grep -q "anonymous FTP login allowed" "$nmap_file"; then
            log "WARNING" "FTP anonimo permitido en $host"
            echo "FTP anonimo: $host" >> "$OUTPUT_DIR/05_insecure_configs.txt"
        fi
        
        if grep -q "SSH server supports older protocols" "$nmap_file"; then
            log "WARNING" "SSH legacy protocols en $host"
            echo "SSH legacy: $host" >> "$OUTPUT_DIR/05_insecure_configs.txt"
        fi
        
    done < "$OUTPUT_DIR/02_live_hosts.txt"
}

# Fase 4: Análisis web (si aplica)
web_analysis_phase() {
    local web_count
    web_count=$(wc -l < "$OUTPUT_DIR/03_web_services.txt" 2>/dev/null || echo 0)
    
    if [ "$web_count" -eq 0 ]; then
        log "INFO" "No hay servicios web para analizar"
        return
    fi
    
    log "INFO" "=== FASE 4: ANALISIS WEB ==="
    
    mkdir -p "$OUTPUT_DIR/web_analysis"
    
    while IFS= read -r host; do
        log "INFO" "Analizando servicio web en: $host"
        
        # Determinar protocolo y puerto
        local protocol="http"
        local port=80
        
        if grep -q "443/open" "$OUTPUT_DIR/services/analysis_${host}.nmap"; then
            protocol="https"
            port=443
        fi
        
        local url="$protocol://$host"
        
        # Análisis básico con curl
        if command -v curl &> /dev/null; then
            log "INFO" "  - Realizando analisis HTTP en $url"
            
            # Headers de seguridad
            curl -I --connect-timeout 5 "$url" 2>/dev/null > "$OUTPUT_DIR/web_analysis/headers_$host.txt" &
            
            # Información del servidor
            curl -s --connect-timeout 5 "$url" 2>/dev/null | head -100 > "$OUTPUT_DIR/web_analysis/content_$host.txt" &
        fi
        
    done < "$OUTPUT_DIR/03_web_services.txt"
    
    wait
    log "SUCCESS" "Analisis web completado"
}

# Fase 5: Generación de reportes
reporting_phase() {
    log "INFO" "=== FASE 5: GENERACION DE REPORTES ==="
    
    # Reporte ejecutivo
    generate_executive_report
    
    # Reporte técnico
    generate_technical_report
    
    # Reporte de seguridad
    generate_security_report
    
    log "SUCCESS" "Reportes generados"
}

# Generar reporte ejecutivo
generate_executive_report() {
    local host_count
    host_count=$(wc -l < "$OUTPUT_DIR/02_live_hosts.txt")
    
    local web_count
    web_count=$(wc -l < "$OUTPUT_DIR/03_web_services.txt" 2>/dev/null || echo 0)
    
    local risky_count
    risky_count=$(wc -l < "$OUTPUT_DIR/03_risky_services.txt" 2>/dev/null || echo 0)
    
    {
        echo "REPORTE EJECUTIVO - PIPELINE DE SEGURIDAD"
        echo "=========================================="
        echo "Fecha: $(date)"
        echo "Target: $TARGET"
        echo "Modo: $MODE"
        echo ""
        echo "RESUMEN EJECUTIVO"
        echo "-----------------"
        echo "Hosts descubiertos: $host_count"
        echo "Servicios web: $web_count"
        echo "Servicios riesgosos: $risky_count"
        echo ""
        echo "HALLAZGOS PRINCIPALES"
        echo "---------------------"
        
        if [ -f "$OUTPUT_DIR/04_obsolete_versions.txt" ]; then
            echo "Versiones obsoletas detectadas:"
            grep "HOST:" "$OUTPUT_DIR/04_obsolete_versions.txt" | head -5
            echo ""
        fi
        
        if [ -f "$OUTPUT_DIR/05_insecure_configs.txt" ]; then
            echo "Configuraciones inseguras:"
            cat "$OUTPUT_DIR/05_insecure_configs.txt"
            echo ""
        fi
        
        echo "RECOMENDACIONES"
        echo "---------------"
        echo "1. Revisar servicios riesgosos identificados"
        echo "2. Actualizar versiones obsoletas"
        echo "3. Fortalecer configuraciones inseguras"
        echo "4. Implementar monitoreo continuo"
        
    } > "$OUTPUT_DIR/06_executive_report.txt"
}

# Generar reporte técnico
generate_technical_report() {
    {
        echo "REPORTE TECNICO DETALLADO"
        echo "========================="
        echo ""
        echo "HERRAMIENTAS UTILIZADAS"
        echo "-----------------------"
        echo "RustScan: $(rustscan --version 2>/dev/null | head -1 || echo 'No disponible')"
        echo "Nmap: $(nmap --version 2>/dev/null | head -1 || echo 'No disponible')"
        echo ""
        echo "CONFIGURACION"
        echo "-------------"
        echo "RustScan options: $RUSTSCAN_OPTS"
        echo "Modo: $MODE"
        echo "Profundidad: $SCAN_DEPTH"
        echo ""
        echo "RESULTADOS DETALLADOS"
        echo "---------------------"
        echo ""
        
        while IFS= read -r host; do
            echo "HOST: $host"
            echo "------"
            if [ -f "$OUTPUT_DIR/services/analysis_${host}.nmap" ]; then
                grep "open" "$OUTPUT_DIR/services/analysis_${host}.nmap" | head -10
            else
                echo "No hay datos de escaneo"
            fi
            echo ""
        done < "$OUTPUT_DIR/02_live_hosts.txt"
        
    } > "$OUTPUT_DIR/07_technical_report.txt"
}

# Generar reporte de seguridad
generate_security_report() {
    {
        echo "REPORTE DE SEGURIDAD"
        echo "===================="
        echo ""
        echo "HALLAZGOS DE SEGURIDAD"
        echo "----------------------"
        echo ""
        
        # Versiones obsoletas
        if [ -f "$OUTPUT_DIR/04_obsolete_versions.txt" ] && [ -s "$OUTPUT_DIR/04_obsolete_versions.txt" ]; then
            echo "VERSIONES OBSOLETAS:"
            cat "$OUTPUT_DIR/04_obsolete_versions.txt"
            echo ""
        fi
        
        # Configuraciones inseguras
        if [ -f "$OUTPUT_DIR/05_insecure_configs.txt" ] && [ -s "$OUTPUT_DIR/05_insecure_configs.txt" ]; then
            echo "CONFIGURACIONES INSEGURAS:"
            cat "$OUTPUT_DIR/05_insecure_configs.txt"
            echo ""
        fi
        
        # Servicios riesgosos
        if [ -s "$OUTPUT_DIR/03_risky_services.txt" ]; then
            echo "SERVICIOS RIESGOSOS:"
            cat "$OUTPUT_DIR/03_risky_services.txt"
            echo ""
        fi
        
        echo "PRIORIDADES DE MITIGACION"
        echo "-------------------------"
        echo "1. Servicios con versiones obsoletas"
        echo "2. Configuraciones inseguras"
        echo "3. Servicios riesgosos expuestos"
        echo "4. Servicios críticos sin hardening"
        
    } > "$OUTPUT_DIR/08_security_report.txt"
}

# Función principal
main() {
    log "INFO" "Iniciando pipeline completo de seguridad"
    log "INFO" "Target: $TARGET"
    log "INFO" "Modo: $MODE"
    
    # Verificaciones iniciales
    check_tools
    
    # Ejecutar pipeline
    local host_count
    host_count=$(discovery_phase)
    
    if [ "$host_count" -eq 0 ]; then
        log "WARNING" "No se encontraron hosts activos"
        exit 0
    fi
    
    service_analysis_phase "$host_count"
    security_assessment_phase
    web_analysis_phase
    reporting_phase
    
    # Resumen final
    log "SUCCESS" "Pipeline completado exitosamente"
    log "INFO" "Reportes generados en: $OUTPUT_DIR"
    log "INFO" "Archivos principales:"
    log "INFO" "  - Reporte ejecutivo: 06_executive_report.txt"
    log "INFO" "  - Reporte tecnico: 07_technical_report.txt"
    log "INFO" "  - Reporte seguridad: 08_security_report.txt"
}

# Manejo de señales
trap 'log "ERROR" "Pipeline interrumpido por el usuario"; exit 1' INT TERM

# Ejecución
if [ $# -eq 0 ]; then
    echo "Uso: $0 <target> [mode]"
    echo "Target: IP, rango o archivo con targets"
    echo "Modos: quick, comprehensive, stealth"
    echo "Ejemplo: $0 192.168.1.0/24 comprehensive"
    exit 1
fi

main "$@"