#!/usr/bin/env python3
# coding=utf-8

# Retorna os metadados relevantes de um IP específico via Shodan.

import shodan
import json
import os
import sys

from dotenv import load_dotenv
load_dotenv()
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")

def fetch_shodan_context(ip_address):
    api = shodan.Shodan(SHODAN_API_KEY)
    
    try:
        print(f"[*] Consultando IP: {ip_address}...")
        host = api.host(ip_address)
        
        # Extraindo apenas os dados relevantes para o Cloud Telescope
        relevant_data = {
            "ip": ip_address,
            "org": host.get("org", "Unknown"),
            "isp": host.get("isp", "Unknown"),
            "ports": sorted(host.get("ports", [])),
            "vulns": list(host.get("vulns", {}).keys()),
            "tags": host.get("tags", []),
            "os": host.get("os", "Unknown"),
            "hostnames": host.get("hostnames", [])
        }
        
        return relevant_data

    except shodan.APIError as e:
        print(f"[!] Erro na API do Shodan: {e}")
        return None

if __name__ == "__main__":
    # Exemplo com um IP de DNS público do Google (apenas para teste inicial)
    # Substitua por um IP malicioso capturado no seu dataset para testar as tags e vulns
    ip_to_test = sys.argv[1] if len(sys.argv) > 1 else "8.8.8.8"
    
    resultado = fetch_shodan_context(ip_to_test)
    
    if resultado:
        print("\n[+] Dados Relevantes Retornados:")
        print(json.dumps(resultado, indent=4))