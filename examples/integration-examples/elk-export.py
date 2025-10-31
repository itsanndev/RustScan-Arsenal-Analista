#!/usr/bin/env python3
"""
Exportacion a ELK Stack
Exporta resultados de escaneo a Elasticsearch para visualizacion en Kibana
"""

import json
import requests
from datetime import datetime
import xml.etree.ElementTree as ET

class ELKExporter:
    def __init__(self, elasticsearch_host="http://localhost:9200", index_prefix="rustscan"):
        self.es_host = elasticsearch_host
        self.index_prefix = index_prefix
        self.session = requests.Session()
        
    def create_index_template(self):
        """
        Crea template de indice para resultados de escaneo
        """
        template = {
            "index_patterns": [f"{self.index_prefix}-*"],
            "mappings": {
                "properties": {
                    "timestamp": {"type": "date"},
                    "scanner": {"type": "keyword"},
                    "target": {"type": "keyword"},
                    "port": {"type": "integer"},
                    "protocol": {"type": "keyword"},
                    "state": {"type": "keyword"},
                    "service": {"type": "keyword"},
                    "version": {"type": "text"},
                    "scan_type": {"type": "keyword"},
                    "risk_level": {"type": "keyword"}
                }
            }
        }
        
        try:
            response = self.session.put(
                f"{self.es_host}/_index_template/{self.index_prefix}-template",
                json=template
            )
            
            if response.status_code in [200, 201]:
                print("[+] Template de indice creado exitosamente")
                return True
            else:
                print(f"[-] Error creando template: {response.text}")
                return False
                
        except Exception as e:
            print(f"[-] Error conectando a Elasticsearch: {e}")
            return False
    
    def export_nmap_results(self, xml_file, scan_type="comprehensive"):
        """
        Exporta resultados de Nmap a Elasticsearch
        """
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            timestamp = datetime.utcnow().isoformat()
            index_name = f"{self.index_prefix}-{datetime.now().strftime('%Y-%m-%d')}"
            
            documents = []
            
            for host in root.findall("host"):
                address_elem = host.find("address[@addrtype='ipv4']")
                if address_elem is None:
                    continue
                
                target_ip = address_elem.get("addr")
                
                ports_elem = host.find("ports")
                if ports_elem is not None:
                    for port in ports_elem.findall("port"):
                        port_data = {
                            "timestamp": timestamp,
                            "scanner": "nmap",
                            "target": target_ip,
                            "port": int(port.get("portid")),
                            "protocol": port.get("protocol"),
                            "scan_type": scan_type
                        }
                        
                        state_elem = port.find("state")
                        if state_elem is not None:
                            port_data["state"] = state_elem.get("state")
                        
                        service_elem = port.find("service")
                        if service_elem is not None:
                            port_data["service"] = service_elem.get("name")
                            port_data["version"] = service_elem.get("version", "")
                        
                        # Determinar nivel de riesgo basico
                        port_data["risk_level"] = self.assess_risk_level(port_data)
                        
                        documents.append(port_data)
            
            # Enviar documentos a Elasticsearch
            return self.bulk_index_documents(index_name, documents)
            
        except Exception as e:
            print(f"[-] Error procesando archivo Nmap: {e}")
            return False
    
    def export_rustscan_results(self, results_file):
        """
        Exporta resultados de RustScan a Elasticsearch
        """
        try:
            with open(results_file, 'r') as f:
                results = json.load(f)
            
            timestamp = datetime.utcnow().isoformat()
            index_name = f"{self.index_prefix}-{datetime.now().strftime('%Y-%m-%d')}"
            
            documents = []
            
            for result in results.get("scan_results", []):
                doc = {
                    "timestamp": timestamp,
                    "scanner": "rustscan",
                    "target": result.get("target"),
                    "ports": result.get("open_ports", []),
                    "scan_duration": result.get("scan_duration"),
                    "risk_level": "informational"
                }
                documents.append(doc)
            
            return self.bulk_index_documents(index_name, documents)
            
        except Exception as e:
            print(f"[-] Error procesando resultados de RustScan: {e}")
            return False
    
    def bulk_index_documents(self, index_name, documents):
        """
        Indexa documentos en Elasticsearch usando bulk API
        """
        if not documents:
            print("[-] No hay documentos para indexar")
            return False
        
        bulk_data = ""
        for doc in documents:
            bulk_data += json.dumps({"index": {}}) + "\n"
            bulk_data += json.dumps(doc) + "\n"
        
        try:
            response = self.session.post(
                f"{self.es_host}/{index_name}/_bulk",
                data=bulk_data,
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code == 200:
                result = response.json()
                if not result.get("errors"):
                    print(f"[+] {len(documents)} documentos indexados exitosamente")
                    return True
                else:
                    print(f"[-] Errores en bulk index: {result}")
                    return False
            else:
                print(f"[-] Error en bulk request: {response.text}")
                return False
                
        except Exception as e:
            print(f"[-] Error enviando datos a Elasticsearch: {e}")
            return False
    
    def assess_risk_level(self, port_data):
        """
        Evalua el nivel de riesgo basado en puerto y servicio
        """
        high_risk_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379]
        
        port = port_data.get("port", 0)
        service = port_data.get("service", "")
        state = port_data.get("state", "")
        
        if state != "open":
            return "closed"
        
        if port in high_risk_ports:
            return "high"
        elif port < 1024:
            return "medium"
        else:
            return "low"

def main():
    import sys
    
    if len(sys.argv) < 3:
        print("Uso: python3 elk-export.py <tipo> <archivo>")
        print("Tipos: nmap, rustscan")
        sys.exit(1)
    
    exporter = ELKExporter()
    
    # Crear template primero
    exporter.create_index_template()
    
    scan_type = sys.argv[1]
    file_path = sys.argv[2]
    
    if scan_type == "nmap":
        exporter.export_nmap_results(file_path)
    elif scan_type == "rustscan":
        exporter.export_rustscan_results(file_path)
    else:
        print("[-] Tipo no soportado. Use: nmap, rustscan")

if __name__ == "__main__":
    main()