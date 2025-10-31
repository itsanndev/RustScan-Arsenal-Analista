#!/usr/bin/env python3
"""
Integración Avanzada con Nmap
Integra capacidades de escaneo de Nmap con análisis de vulnerabilidades
Compatible con resultados de RustScan
"""

import subprocess
import json
import xml.etree.ElementTree as ET
import sys
from pathlib import Path

class NmapIntegration:
    def __init__(self):
        self.scan_results = {}
        
    def advanced_scan(self, target, scan_type="comprehensive"):
        """
        Realiza escaneos avanzados de Nmap con diferentes perfiles
        """
        scan_profiles = {
            "comprehensive": "-sS -sV -sC -O -A --script vuln",
            "stealth": "-sS -T2 -f -D RND:10 --script safe",
            "vulnerability": "-sV --script vuln,vuln-showmore",
            "discovery": "-sn -PE -PP -PS21,22,23,25,80,113,443 -PA80,113,443"
        }
        
        scan_args = scan_profiles.get(scan_type, "-sS -sV -sC")
        output_file = f"scan_{target.replace('/', '_')}.xml"
        
        try:
            cmd = f"nmap {scan_args} -oX {output_file} {target}"
            print(f"[*] Ejecutando escaneo: {cmd}")
            
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                return self.parse_nmap_xml(output_file)
            else:
                print(f"[-] Error en escaneo: {result.stderr}")
                return None
                
        except Exception as e:
            print(f"[-] Excepcion durante escaneo: {e}")
            return None
    
    def parse_nmap_xml(self, xml_file):
        """
        Parsea resultados XML de Nmap y extrae informacion estructurada
        """
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            scan_data = {
                "target": "",
                "hosts": [],
                "scan_info": {}
            }
            
            for host in root.findall("host"):
                host_data = {
                    "address": "",
                    "status": "",
                    "ports": []
                }
                
                # Direccion IP
                address_elem = host.find("address[@addrtype='ipv4']")
                if address_elem is not None:
                    host_data["address"] = address_elem.get("addr")
                
                # Estado del host
                status_elem = host.find("status")
                if status_elem is not None:
                    host_data["status"] = status_elem.get("state")
                
                # Puertos y servicios
                ports_elem = host.find("ports")
                if ports_elem is not None:
                    for port in ports_elem.findall("port"):
                        port_data = {
                            "port": port.get("portid"),
                            "protocol": port.get("protocol"),
                            "state": "",
                            "service": ""
                        }
                        
                        state_elem = port.find("state")
                        if state_elem is not None:
                            port_data["state"] = state_elem.get("state")
                        
                        service_elem = port.find("service")
                        if service_elem is not None:
                            port_data["service"] = service_elem.get("name")
                            port_data["version"] = service_elem.get("version", "")
                        
                        host_data["ports"].append(port_data)
                
                scan_data["hosts"].append(host_data)
            
            return scan_data
            
        except Exception as e:
            print(f"[-] Error parseando XML: {e}")
            return None
    
    def rustscan_to_nmap(self, rustscan_ports, target):
        """
        Toma puertos descubiertos por RustScan y realiza escaneo detallado con Nmap
        """
        if not rustscan_ports:
            print("[-] No hay puertos para escanear")
            return None
        
        ports_str = ",".join(rustscan_ports)
        cmd = f"nmap -sV -sC -p {ports_str} -oX rustscan_followup.xml {target}"
        
        print(f"[*] Ejecutando Nmap en puertos descubiertos por RustScan: {ports_str}")
        
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if result.returncode == 0:
                return self.parse_nmap_xml("rustscan_followup.xml")
            else:
                print(f"[-] Error en escaneo Nmap: {result.stderr}")
                return None
        except Exception as e:
            print(f"[-] Excepcion: {e}")
            return None

def main():
    if len(sys.argv) < 2:
        print("Uso: python3 nmap-integration.py <target> [scan_type]")
        print("Scan types: comprehensive, stealth, vulnerability, discovery")
        sys.exit(1)
    
    target = sys.argv[1]
    scan_type = sys.argv[2] if len(sys.argv) > 2 else "comprehensive"
    
    nmap = NmapIntegration()
    results = nmap.advanced_scan(target, scan_type)
    
    if results:
        print("[+] Escaneo completado exitosamente")
        print(json.dumps(results, indent=2))
    else:
        print("[-] El escaneo fallo")

if __name__ == "__main__":
    main()