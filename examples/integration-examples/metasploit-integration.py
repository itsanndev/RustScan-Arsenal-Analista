#!/usr/bin/env python3
"""
Integracion con Metasploit Framework
Automatiza tareas comunes de Metasploit basado en resultados de escaneo
"""

import subprocess
import json
import time
from pathlib import Path

class MetasploitIntegration:
    def __init__(self):
        self.workspace = "rustscan_automation"
        self.results_file = "metasploit_results.json"
    
    def setup_workspace(self):
        """
        Configura el workspace de Metasploit para la automatizacion
        """
        commands = [
            f"workspace -a {self.workspace}",
            f"workspace {self.workspace}"
        ]
        
        return self.execute_msf_commands(commands)
    
    def import_scan_results(self, nmap_xml_file):
        """
        Importa resultados de escaneo Nmap/RustScan a Metasploit
        """
        if not Path(nmap_xml_file).exists():
            print(f"[-] Archivo no encontrado: {nmap_xml_file}")
            return False
        
        commands = [
            f"db_import {nmap_xml_file}",
            "services"  # Listar servicios importados
        ]
        
        return self.execute_msf_commands(commands)
    
    def execute_msf_commands(self, commands):
        """
        Ejecuta comandos de Metasploit a traves de msfconsole
        """
        try:
            cmd_file = "msf_commands.rc"
            
            # Crear archivo de comandos
            with open(cmd_file, 'w') as f:
                for command in commands:
                    f.write(f"{command}\n")
                f.write("exit\n")
            
            # Ejecutar msfconsole con los comandos
            result = subprocess.run(
                f"msfconsole -q -r {cmd_file}",
                shell=True,
                capture_output=True,
                text=True
            )
            
            print("[*] Comandos de Metasploit ejecutados")
            print(result.stdout)
            
            # Limpiar archivo temporal
            Path(cmd_file).unlink(missing_ok=True)
            
            return True
            
        except Exception as e:
            print(f"[-] Error ejecutando comandos de Metasploit: {e}")
            return False
    
    def automated_vulnerability_scan(self, target):
        """
        Ejecuta escaneo automatizado de vulnerabilidades
        """
        commands = [
            f"use auxiliary/scanner/portscan/tcp",
            f"set RHOSTS {target}",
            "set PORTS 1-1000",
            "run",
            "back",
            "use auxiliary/scanner/http/http_version",
            f"set RHOSTS {target}",
            "run"
        ]
        
        return self.execute_msf_commands(commands)
    
    def generate_exploitation_report(self):
        """
        Genera reporte de posibles vectores de explotacion
        """
        commands = [
            "hosts",
            "services",
            "vulns",
            "loot"
        ]
        
        return self.execute_msf_commands(commands)

def main():
    msf = MetasploitIntegration()
    
    # Ejemplo de uso
    if msf.setup_workspace():
        print("[+] Workspace configurado exitosamente")
        
        # Importar resultados de escaneo previo
        if len(sys.argv) > 1:
            scan_file = sys.argv[1]
            msf.import_scan_results(scan_file)
        
        # Ejecutar escaneo de vulnerabilidades
        if len(sys.argv) > 2:
            target = sys.argv[2]
            msf.automated_vulnerability_scan(target)
        
        msf.generate_exploitation_report()

if __name__ == "__main__":
    import sys
    main()