import shodan
import json
import os
import sys

from dotenv import load_dotenv
load_dotenv()
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")

if not SHODAN_API_KEY:
    print("[ERRO]: A variável SHODAN_API_KEY não foi definida no arquivo .env", file=sys.stderr)
    sys.exit(1)

api = shodan.Shodan(SHODAN_API_KEY)

host = api.host("185.220.101.1")  # exemplo: Tor exit node comum em capturas IBR
#host = api.host("102.38.199.7")  # exemplo: Tor exit node comum em capturas IBR

# Opção 1: ver só as chaves do nível raiz
print(host.keys())

# Opção 2: dump completo formatado (cuidado — pode ser longo)
print(json.dumps(host, indent=2, default=str))

# Opção 3: ver as chaves de cada serviço dentro de 'data'
for service in host['data']:
    print(service.keys())
    break  # só o primeiro para não repetir

'''
A resposta varia por IP — um IP com SSH aberto terá campos que um IP só com HTTP não tem. Não existe uma lista fixa universal, o schema é dinâmico.

**Campos que aparecem consistentemente no nível raiz:**
ip_str, country_name, country_code, city, region_code,
org, isp, asn, os, tags, ports, hostnames, domains,
last_update, latitude, longitude
'''

'''
**Campos que aparecem dentro de cada item de `data`** (por serviço):
port, transport, ip_str, timestamp, data (banner),
product, version, cpe, info, devicetype,
ssl (se HTTPS), http (se web), ssh (se SSH), vulns
'''
