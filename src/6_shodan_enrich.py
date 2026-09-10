#!/usr/bin/python3
# coding=utf-8
"""
Módulo de Integração com a API do Shodan
Cloud Telescope - Pipeline de Enriquecimento Técnico de IPs (RF01-RF07)

Estende o pipeline existente adicionando metadados OSINT do Shodan
a cada endereço IP de origem. Os seguintes campos são adicionados ao CSV
(posições 18 a 27, após a coluna awsregion):

  18  shodan_org          Organização/empresa proprietária do IP
  19  shodan_isp          Provedor de serviços de internet
  20  shodan_asn          Autonomous System Number (ex: AS15169)
  21  shodan_os           Sistema operacional detectado via banner grabbing
  22  shodan_open_ports   Portas abertas detectadas (separadas por |)
  23  shodan_cpes         Common Platform Enumeration de todos os serviços (separados por |)
  24  shodan_cves         CVEs conhecidos associados ao host (separados por |)
  25  shodan_tags         Tags Shodan atribuídas ao host (ex: cloud|vpn|tor)
  26  shodan_hostnames    Hostnames resolvidos para o IP (separados por |)
  27  shodan_last_seen    Timestamp do último scan do Shodan

Modos de uso:

  [PIPELINE] Integração ao ETL existente:
    zcat output.csv.enriched.gz | python3 6_shodan_enrich.py | gzip > output.csv.shodan.gz
    (--cache-save-every N controla a frequência de gravação do cache em disco)

  Interrupção graciosa de coleta longa (criação manual do arquivo marcador):
    touch PARAR   # encerra ao fim da linha corrente, com flush do cache e .gz íntegro

  [DEMO] Visualização detalhada da resposta da API para um IP:
    python3 6_shodan_enrich.py --demo 1.2.3.4

  [DEMO JSON] Dump da resposta bruta em JSON:
    python3 6_shodan_enrich.py --demo 1.2.3.4 --json

  [INFO API] Consulta informações e créditos da chave da API:
    python3 6_shodan_enrich.py --info

Configuração da chave de API (RF03 - CSU01):
  export SHODAN_API_KEY="sua_chave_aqui"
  ou via argumento: python3 6_shodan_enrich.py --api-key "sua_chave_aqui"

Requisitos:
  pip install shodan

Riscos gerenciados:
  - Esgotamento de créditos: cache local evita consultar o mesmo IP duas vezes
  - Rate limit: delay configurável entre requisições (RNF03)
  - IPs sem registro: tratados silenciosamente com campos vazios (RNF04)
  - Timeouts e falhas de rede: retentativas com backoff exponencial (RNF04)
"""

import sys
import os
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

import json
import re
import time
import atexit
import tempfile
import logging
import argparse
from datetime import datetime, timezone
from pathlib import Path

try:
    import shodan
except ImportError:
    print(
        "ERRO: biblioteca 'shodan' não encontrada.\n"
        "Execute: pip install shodan",
        file=sys.stderr
    )
    sys.exit(1)


from dotenv import load_dotenv
load_dotenv(os.path.join(PROJECT_ROOT, '.env'))
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")

if not SHODAN_API_KEY:
    print("[ERRO]: A variável SHODAN_API_KEY não foi definida no arquivo .env", file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------------------
# Configurações padrão
# ---------------------------------------------------------------------------

CACHE_FILE      = os.path.join(PROJECT_ROOT, "logs", "shodan_cache.json") # RF06 - persistência local
RATE_LIMIT_SEC  = 1.0                       # RNF03 - plano acadêmico: 1 req/s
MAX_RETRIES     = 3                         # RNF04 - tentativas em falhas de rede
RETRY_BACKOFF   = 10                        # segundos de espera na primeira retentativa
LOG_FILE        = os.path.join(PROJECT_ROOT, "logs", "shodan_enrich.log")
PROGRESS_EVERY  = 1000                      # linhas entre cada log de progresso
RATE_LIMIT_WAIT = 60                        # espera fixa ao retentar em rate limit (RNF03)
DEFAULT_SAVE_EVERY = 500                    # grava o cache em disco a cada N IPs novos (RF06)
IPV4_RE         = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

# Nomes dos campos adicionados ao CSV (usados no modo demo e no cabeçalho)
SHODAN_FIELD_NAMES = [
    "shodan_org",
    "shodan_isp",
    "shodan_asn",
    "shodan_os",
    "shodan_open_ports",
    "shodan_cpes",
    "shodan_cves",
    "shodan_tags",
    "shodan_hostnames",
    "shodan_last_seen",
]

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(sys.stderr),
    ],
)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Cache local (RF06 / CSU02 - Fluxo Alternativo A1)
# ---------------------------------------------------------------------------

class ShodanCache:
    """
    Cache em arquivo JSON com IP como chave primária (RF06).

    Garante que o mesmo IP nunca seja consultado duas vezes na API,
    preservando os créditos acadêmicos (Quadro 2 - Risco: Esgotamento de créditos).

    Formato interno:
    {
        "1.2.3.4": {
            "found": true,
            "org": "...",
            "open_ports": [22, 80],
            "cves": ["CVE-2021-44228"],
            ...
        },
        ...
    }
    """

    def __init__(self, filepath: str, save_every: int = DEFAULT_SAVE_EVERY):
        self.filepath = filepath
        self.save_every = max(1, save_every)
        self.data: dict = {}
        self._hits = 0
        self._misses = 0
        self._pending = 0
        self._load()

    def _load(self):
        if Path(self.filepath).exists():
            try:
                with open(self.filepath, "r", encoding="utf-8") as f:
                    self.data = json.load(f)
                logger.info(f"Cache carregado: {len(self.data)} IPs em '{self.filepath}'")
            except (json.JSONDecodeError, OSError) as e:
                logger.warning(f"Cache ilegível ({e}), iniciando vazio.")
                self.data = {}
        else:
            logger.info(f"Cache não encontrado, será criado: '{self.filepath}'")

    def get(self, ip: str) -> dict | None:
        record = self.data.get(ip)
        if record is not None:
            self._hits += 1
        else:
            self._misses += 1
        return record

    def set(self, ip: str, record: dict):
        self.data[ip] = self._slim(record)
        self._pending += 1
        if self._pending >= self.save_every:
            self._save()

    def flush(self):
        """Força a gravação das pendências do cache em disco."""
        if self._pending > 0:
            self._save()

    def _save(self):
        """Grava o cache em disco de forma atômica (temporário + os.replace)."""
        try:
            diretorio = os.path.dirname(os.path.abspath(self.filepath))
            fd, caminho_tmp = tempfile.mkstemp(
                dir=diretorio, prefix=".shodan_cache_", suffix=".tmp"
            )
        except OSError as e:
            logger.error(f"Falha ao salvar cache (criar temporário): {e}")
            return
        substituido = False
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(self.data, f, ensure_ascii=False)
                f.flush()
                os.fsync(f.fileno())
            os.replace(caminho_tmp, self.filepath)
            substituido = True
        except OSError as e:
            logger.error(f"Falha ao salvar cache: {e}")
        finally:
            if not substituido:
                try:
                    os.unlink(caminho_tmp)
                except OSError:
                    pass
        if substituido:
            self._pending = 0

    @staticmethod
    def _slim(record: dict) -> dict:
        """Remove campos auxiliares pesados (banners/certs completos) do cache."""
        return {k: v for k, v in record.items() if k != "_raw_services"}

    @property
    def stats(self) -> dict:
        return {
            "cached_ips": len(self.data),
            "cache_hits": self._hits,
            "cache_misses": self._misses,
        }

    def __len__(self):
        return len(self.data)


# ---------------------------------------------------------------------------
# Autenticação e conexão (RF03 / CSU01)
# ---------------------------------------------------------------------------

def init_api(api_key: str) -> shodan.Shodan:
    """
    Inicializa e valida a conexão com a API do Shodan (RF03 / CSU01).
    Registra créditos disponíveis e plano ativo.
    """
    api = shodan.Shodan(api_key)
    try:
        info = api.info()
        logger.info(
            f"[API OK] Plano: '{info.get('plan', 'desconhecido')}' | "
            f"Créditos de consulta: {info.get('query_credits', 'N/A')} | "
            f"Créditos de scan: {info.get('scan_credits', 'N/A')}"
        )
    except shodan.APIError as e:
        logger.error(f"[API ERROR] Falha de autenticação: {e}")
        logger.error("Verifique a variável SHODAN_API_KEY foi definida no arquivo .env ou o argumento --api-key.")
        sys.exit(1)
    return api


# ---------------------------------------------------------------------------
# Consulta e normalização (RF04, RF05 / CSU02)
# ---------------------------------------------------------------------------

def _normalize_host(host: dict, ip: str) -> dict:
    """
    Converte a resposta bruta de api.host() em registro normalizado (RF04, RF05).
    Reutilizado pelo modo pipeline (via query_shodan) e pelo modo demo.
    """
    # Consolida CPEs de todos os serviços detectados (RF05)
    cpes: set[str] = set()
    for service in host.get("data", []):
        for cpe in service.get("cpe", []):
            cpes.add(cpe)

    # CVEs: a API retorna dict {CVE_ID: metadata} em planos completos,
    # ou lista [CVE_ID, ...] em planos com acesso parcial (RF05).
    vulns_raw = host.get("vulns", {})
    if isinstance(vulns_raw, dict):
        cves = sorted(vulns_raw.keys())
    elif isinstance(vulns_raw, list):
        cves = sorted(vulns_raw)
    else:
        cves = []

    record = {
        "found":       True,
        "org":         _clean(host.get("org",  "")),
        "isp":         _clean(host.get("isp",  "")),
        "asn":         _clean(host.get("asn",  "")),
        "os":          _clean(host.get("os") or ""),
        "open_ports":  sorted(host.get("ports", [])),
        "cpes":        sorted(cpes),
        "cves":        cves,
        "tags":        host.get("tags", []),
        "hostnames":   host.get("hostnames", []),
        "last_seen":   host.get("last_update", ""),
        # Campos auxiliares (não exportados para CSV, usados em logs/demo)
        "_services_count": len(host.get("data", [])),
        "_raw_services":   host.get("data", []),
        "_queried_at":     datetime.now(timezone.utc).isoformat(),
    }

    logger.info(
        f"[FOUND] {ip} | org='{record['org']}' | "
        f"portas={len(record['open_ports'])} | "
        f"serviços={record['_services_count']} | "
        f"CPEs={len(record['cpes'])} | "
        f"CVEs={len(record['cves'])}"
    )
    return record


def query_shodan(api: shodan.Shodan, ip: str, retries: int = MAX_RETRIES) -> dict:
    """
    Consulta api.host(ip) e normaliza o resultado (RF04, RF05).

    Campos extraídos da resposta:
      - org, isp, asn          : identificação da infraestrutura
      - os                     : sistema operacional (banner grabbing)
      - ports                  : lista de portas abertas detectadas
      - data[].cpe             : CPEs de cada serviço (RF05)
      - vulns                  : chaves = CVE IDs (RF05)
      - tags                   : classificações Shodan (cloud, vpn, tor...)
      - hostnames              : resolução reversa de DNS
      - last_update            : timestamp do último scan

    Tratamento de erros (RNF04 / CSU02 - Fluxos de exceção):
      - IP sem registros    → retorna registro vazio, sem exception
      - Rate limit          → pausa RATE_LIMIT_WAIT e retenta (limitado a MAX_RETRIES)
      - Falha de rede       → backoff exponencial até MAX_RETRIES tentativas
    """
    try:
        host = api.host(ip)
        return _normalize_host(host, ip)

    except shodan.APIError as e:
        error_msg = str(e)

        # CSU02 - Exceção 3: IP sem registros históricos
        if "No information available" in error_msg or "404" in error_msg:
            logger.debug(f"[NO DATA] {ip} — sem registros no Shodan")
            return _empty_record(ip, reason="no_data")

        # CSU02 - Exceção 1: Rate limit (RNF03)
        if "rate limit" in error_msg.lower():
            if retries > 0:
                logger.warning(
                    f"[RATE LIMIT] {ip} — {error_msg}. "
                    f"Pausa de {RATE_LIMIT_WAIT}s antes de retentar "
                    f"({retries} tentativas restantes)..."
                )
                time.sleep(RATE_LIMIT_WAIT)
                return query_shodan(api, ip, retries - 1)
            logger.error(f"[FAIL] {ip} — rate limit persistente: {error_msg}")
            return _empty_record(ip, reason=error_msg[:100])

        # CSU02 - Exceção 2: Falha de rede / timeout (RNF04)
        if retries > 0:
            wait = RETRY_BACKOFF * (MAX_RETRIES - retries + 1)
            logger.warning(
                f"[TIMEOUT] {ip} — {error_msg}. "
                f"Retentando em {wait}s ({retries} tentativas restantes)..."
            )
            time.sleep(wait)
            return query_shodan(api, ip, retries - 1)

        logger.error(f"[FAIL] {ip} — esgotadas as tentativas: {error_msg}")
        return _empty_record(ip, reason=error_msg[:100])


def _empty_record(ip: str, reason: str = "") -> dict:
    """Registro vazio para IPs sem dados ou com falha de consulta."""
    return {
        "found":       False,
        "org":         "", "isp":       "", "asn":      "", "os": "",
        "open_ports":  [], "cpes":      [], "cves":     [],
        "tags":        [], "hostnames": [], "last_seen": "",
        "_services_count": 0,
        "_raw_services":   [],
        "_queried_at": datetime.now(timezone.utc).isoformat(),
        "_miss_reason": reason,
    }


def _clean(value: str) -> str:
    """Remove vírgulas e quebras de linha que quebrariam o CSV."""
    return str(value).replace(",", " ").replace("\n", " ").replace("\r", "").strip()


def _is_ipv4(value: str) -> bool:
    """Valida se a string é um IPv4 no formato dotted quad."""
    if not IPV4_RE.match(value):
        return False
    return all(0 <= int(octet) <= 255 for octet in value.split("."))


# ---------------------------------------------------------------------------
# Serialização CSV (RF07)
# ---------------------------------------------------------------------------

def record_to_csv_fields(record: dict) -> list[str]:
    """
    Converte um registro Shodan nos 10 campos CSV adicionais (RF07).
    Listas são serializadas com '|' como separador interno.
    """
    def join_list(lst: list) -> str:
        return "|".join(str(x) for x in lst) if lst else ""

    return [
        record.get("org",       ""),    # 18 shodan_org
        record.get("isp",       ""),    # 19 shodan_isp
        record.get("asn",       ""),    # 20 shodan_asn
        record.get("os",        ""),    # 21 shodan_os
        join_list(record.get("open_ports", [])),  # 22 shodan_open_ports
        join_list(record.get("cpes",       [])),  # 23 shodan_cpes
        join_list(record.get("cves",       [])),  # 24 shodan_cves
        join_list(record.get("tags",       [])),  # 25 shodan_tags
        join_list(record.get("hostnames",  [])),  # 26 shodan_hostnames
        record.get("last_seen", ""),    # 27 shodan_last_seen
    ]


# ---------------------------------------------------------------------------
# Modo DEMO (mostra estrutura e conteúdo da resposta Shodan)
# ---------------------------------------------------------------------------

def demo_mode(api: shodan.Shodan, ip: str, dump_json: bool = False):
    """
    Consulta o Shodan para um IP e exibe a resposta de forma estruturada.
    Objetivo: evidenciar quais campos são retornados e como são aproveitados
    no pipeline (CSU02 / Seção 4.3.2 - Descrição da modelagem).
    """
    SEP = "=" * 64

    print(f"\n{SEP}")
    print(f"  DEMO — Consulta Shodan: {ip}")
    print(f"{SEP}")

    try:
        host = api.host(ip)
    except shodan.APIError as e:
        print(f"\n  [ERRO] {e}\n")
        return

    # ----------------------------------------------------------------
    # 1. Metadados de identidade e geolocalização
    # ----------------------------------------------------------------
    print("\n── 1. Identificação e Geolocalização ──────────────────────")
    print(f"  IP:               {host.get('ip_str')}")
    print(f"  Organização:      {host.get('org',          'N/A')}")
    print(f"  ISP:              {host.get('isp',          'N/A')}")
    print(f"  ASN:              {host.get('asn',          'N/A')}")
    print(f"  País:             {host.get('country_name', 'N/A')} ({host.get('country_code', '')})")
    print(f"  Cidade:           {host.get('city',         'N/A')}, {host.get('region_code', '')}")
    print(f"  Coordenadas:      {host.get('latitude')}, {host.get('longitude')}")
    print(f"  Código Postal:    {host.get('postal_code',  'N/A')}")
    print(f"  Domínios:         {host.get('domains',      [])}")
    print(f"  Hostnames:        {host.get('hostnames',    [])}")
    print(f"  Tags Shodan:      {host.get('tags',         [])}")
    print(f"  Último scan:      {host.get('last_update',  'N/A')}")

    # ----------------------------------------------------------------
    # 2. Sistema Operacional e portas
    # ----------------------------------------------------------------
    print("\n── 2. Sistema e Portas ─────────────────────────────────────")
    print(f"  OS detectado:     {host.get('os', 'N/A') or 'Não identificado'}")
    print(f"  Portas abertas:   {host.get('ports', [])}")
    print(f"  Serviços na resp: {len(host.get('data', []))}")

    # ----------------------------------------------------------------
    # 3. Serviços individuais (banner grabbing → CPE)
    # ----------------------------------------------------------------
    print("\n── 3. Serviços Detectados (Banner Grabbing) ────────────────")
    services = host.get("data", [])
    if not services:
        print("  Nenhum serviço na resposta.")
    for i, svc in enumerate(services, 1):
        port      = svc.get("port",      "?")
        transport = svc.get("transport", "tcp")
        product   = svc.get("product",   "")
        version   = svc.get("version",   "")
        cpes      = svc.get("cpe",       [])
        banner    = svc.get("data",      "").strip()

        print(f"\n  [{i}] {port}/{transport} — {product} {version}".rstrip())

        if cpes:
            print(f"       CPE:      {cpes}")

        # Banner: exibe as 3 primeiras linhas, truncado a 120 chars cada
        if banner:
            lines = banner.splitlines()[:3]
            for ln in lines:
                print(f"       Banner:   {ln[:120]}")

        # Certificado SSL/TLS (quando disponível)
        ssl = svc.get("ssl", {})
        if ssl:
            cert    = ssl.get("cert", {})
            subject = cert.get("subject", {})
            issuer  = cert.get("issuer",  {})
            print(f"       SSL CN:   {subject.get('CN', 'N/A')}")
            print(f"       Emissor:  {issuer.get('O',  'N/A')}")
            print(f"       Expira:   {cert.get('expires', 'N/A')}")

        # HTTP info
        http = svc.get("http", {})
        if http:
            print(f"       HTTP:     {http.get('status', '')} | título: {str(http.get('title', ''))[:60]}")

    # ----------------------------------------------------------------
    # 4. CVEs (RF05) — núcleo do enriquecimento qualitativo
    # ----------------------------------------------------------------

    vulns = host.get("vulns", {})
    print(f"\n── 4. CVEs Conhecidos ({len(vulns)} encontrados) ─────────────────")
    if vulns:
        if isinstance(vulns, dict):
            # Plano completo: metadados detalhados disponíveis
            print(f"  {'CVE ID':<20} {'CVSS':>5}  Verificado  Descrição (resumo)")
            print(f"  {'-'*20} {'-'*5}  {'-'*10}  {'-'*40}")
            for cve_id, cve_data in sorted(vulns.items()):
                cvss      = cve_data.get("cvss",     "N/A")
                verified  = "Sim" if cve_data.get("verified") else "Não"
                summary   = cve_data.get("summary",  "")[:60]
                refs      = len(cve_data.get("references", []))
                print(f"  {cve_id:<20} {str(cvss):>5}  {verified:<10}  {summary}...")
                if refs:
                    print(f"  {'':20}       {'':10}  ({refs} referências)")
        elif isinstance(vulns, list):
            # Plano acadêmico/parcial: apenas IDs retornados, sem metadados
            print(f"  (Plano atual retorna apenas IDs — CVSS e descrição indisponíveis)")
            preview = sorted(vulns)[:20]
            for cve_id in preview:
                print(f"  {cve_id}")
            if len(vulns) > 20:
                print(f"  ... e mais {len(vulns) - 20} CVEs")
    else:
        print("  Nenhum CVE registrado para este IP no Shodan.")
        print("  (Nota: CVEs requerem plano acadêmico ou pago)")

    # ----------------------------------------------------------------
    # 5. Campos que serão adicionados ao CSV do pipeline (RF07)
    # ----------------------------------------------------------------
    print("\n── 5. Campos Adicionados ao CSV do Pipeline ────────────────")
    record     = _normalize_host(host, ip)
    csv_fields = record_to_csv_fields(record)
    print(f"  {'Campo CSV':<25} {'Índice':>6}  Valor")
    print(f"  {'-'*25} {'-'*6}  {'-'*40}")
    for idx, (name, value) in enumerate(zip(SHODAN_FIELD_NAMES, csv_fields), start=18):
        display = value if value else "(vazio)"
        # Trunca valores longos para exibição
        if len(display) > 60:
            display = display[:57] + "..."
        print(f"  {name:<25} [{idx:>2}]   {display}")

    # ----------------------------------------------------------------
    # 6. Dump JSON bruto (opcional)
    # ----------------------------------------------------------------
    if dump_json:
        print("\n── 6. Resposta JSON Completa (sem campo 'data') ────────────")
        host_meta = {k: v for k, v in host.items() if k != "data"}
        print(json.dumps(host_meta, indent=2, default=str, ensure_ascii=False))

    print(f"\n{SEP}\n")


# ---------------------------------------------------------------------------
# Modo INFO
# ---------------------------------------------------------------------------

def info_mode(api: shodan.Shodan):
    """Exibe informações da conta e créditos da chave de API (CSU01)."""
    try:
        info = api.info()
        #profile = api.profile()
    except shodan.APIError as e:
        print(f"Erro ao consultar informações da API: {e}", file=sys.stderr)
        return

    print("\n── Informações da Conta Shodan ─────────────────────────────")
    print(f"  Plano:                    {info.get('plan',          'N/A')}")
    print(f"  Créditos de consulta:     {info.get('query_credits', 'N/A')}")
    print(f"  Créditos de scan:         {info.get('scan_credits',  'N/A')}")
    print(f"  Acesso HTTPS:             {info.get('https',         'N/A')}")
    print(f"  Acesso a telnet:          {info.get('telnet',        'N/A')}")
    #print(f"\n  Membro:                   {profile.get('member',  False)}")
    #print(f"  Criado em:                {profile.get('created',   'N/A')}")
    #print(f"  Display name:             {profile.get('display_name', 'N/A')}")
    print()


# ---------------------------------------------------------------------------
# Modo PIPELINE (CSU02 + CSU03)
# ---------------------------------------------------------------------------

def process_pipeline(
    api: shodan.Shodan,
    cache: ShodanCache,
    rate_limit: float,
    stop_file: str | None = None,
):
    """
    Lê CSV enriquecido do stdin (saída de 2_enrich_csv.py), adiciona os
    campos Shodan e escreve no stdout (RF01, RF02, RF06, RF07 / CSU02, CSU03).

    Formato de entrada esperado (18 campos):
      timestamp, ipsrc, ipdst, tcpdstport, tcpdstflags, udpdstport, icmptype,
      src_iso, src_country, src_city, src_lat, src_lon,
      dst_iso, dst_country, dst_city, dst_lat, dst_lon, aws_region

    Formato de saída (28 campos = 18 originais + 10 Shodan):
      ...campos originais..., shodan_org, shodan_isp, shodan_asn, shodan_os,
      shodan_open_ports, shodan_cpes, shodan_cves, shodan_tags,
      shodan_hostnames, shodan_last_seen

    stop_file: caminho de um marcador opcional. Quando o arquivo existir, o
    loop encerra na fronteira entre linhas (após concluir a linha corrente),
    persiste o cache e sai com código 0 — permitindo interromper uma coleta
    longa de forma limpa (sem perder pendências de cache e com o .gz íntegro).
    """
    stats = {
        "lines_total":    0,
        "lines_skipped":  0,
        "cache_hits":     0,
        "api_calls":      0,
        "no_data":        0,
    }
    parou = False

    for rawline in sys.stdin:
        if stop_file and Path(stop_file).exists():
            logger.info(
                f"Marcador de parada detectado ('{stop_file}') — "
                f"encerrando a coleta após {stats['lines_total']} linhas."
            )
            parou = True
            break

        line   = rawline.rstrip("\n\r")
        fields = line.split(",")

        # Valida formato mínimo (RF01)
        if len(fields) < 18:
            logger.warning(
                f"Linha ignorada — esperado ≥18 campos, encontrado {len(fields)}: "
                f"{line[:80]!r}"
            )
            stats["lines_skipped"] += 1
            continue

        stats["lines_total"] += 1
        ipsrc = fields[1]  # RF01 — endereço IPv4 de origem
        if not _is_ipv4(ipsrc):
            logger.warning(
                f"Linha ignorada — IPv4 de origem inválido ({ipsrc!r}): "
                f"{line[:80]!r}"
            )
            stats["lines_skipped"] += 1
            continue

        # RF02 — verifica cache antes de consultar a API
        record = cache.get(ipsrc)
        if record is not None:
            stats["cache_hits"] += 1
        else:
            # CSU02 — consulta API e persiste no cache
            record = query_shodan(api, ipsrc)
            cache.set(ipsrc, record)
            stats["api_calls"] += 1
            if not record.get("found"):
                stats["no_data"] += 1
            time.sleep(rate_limit)

        # RF07 / CSU03 — escreve linha enriquecida no stdout
        csv_fields = record_to_csv_fields(record)
        print(line + "," + ",".join(csv_fields))

        # Log de progresso
        if stats["lines_total"] % PROGRESS_EVERY == 0:
            cs = cache.stats
            logger.info(
                f"Progresso: {stats['lines_total']} linhas | "
                f"cache hits: {cs['cache_hits']} | "
                f"API calls: {stats['api_calls']} | "
                f"sem dados: {stats['no_data']}"
            )

    # Persiste as pendências restantes do cache (RF06)
    cache.flush()

    # Relatório final
    cs = cache.stats
    logger.info("─" * 50)
    if parou:
        logger.info("Encerrado por marcador de parada (--stop-file).")
    else:
        logger.info(f"Concluído.")
    logger.info(f"  Linhas processadas:  {stats['lines_total']}")
    logger.info(f"  Linhas ignoradas:    {stats['lines_skipped']}")
    logger.info(f"  IPs em cache:        {cs['cached_ips']}")
    logger.info(f"  Cache hits:          {cs['cache_hits']}")
    logger.info(f"  API calls:           {stats['api_calls']}")
    logger.info(f"  IPs sem dados:       {stats['no_data']}")
    logger.info("─" * 50)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        prog="6_shodan_enrich.py",
        description=(
            "Módulo de integração Shodan para o pipeline Cloud Telescope.\n"
            "Sem argumentos, lê CSV enriquecido do stdin e escreve no stdout."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--api-key",
        default=SHODAN_API_KEY,
        metavar="CHAVE",
        help="Chave da API Shodan (padrão: variável de ambiente SHODAN_API_KEY)",
    )
    parser.add_argument(
        "--demo",
        metavar="IP",
        help="Modo demonstração: exibe resposta estruturada do Shodan para um IP",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="No modo --demo, inclui dump JSON da resposta bruta ao final",
    )
    parser.add_argument(
        "--info",
        action="store_true",
        help="Exibe informações da conta e créditos disponíveis na API",
    )
    parser.add_argument(
        "--cache-file",
        default=CACHE_FILE,
        metavar="ARQUIVO",
        help=f"Caminho do arquivo de cache JSON (padrão: {CACHE_FILE})",
    )
    parser.add_argument(
        "--rate-limit",
        type=float,
        default=RATE_LIMIT_SEC,
        metavar="SEGUNDOS",
        help=f"Delay entre requisições à API (padrão: {RATE_LIMIT_SEC}s)",
    )
    parser.add_argument(
        "--cache-save-every",
        type=int,
        default=DEFAULT_SAVE_EVERY,
        metavar="N",
        help=f"Grava o cache em disco a cada N IPs novos (padrão: {DEFAULT_SAVE_EVERY})",
    )
    parser.add_argument(
        "--stop-file",
        default=None,
        metavar="ARQUIVO",
        help="Caminho de um marcador: quando o arquivo existir, a coleta encerra "
             "graciosamente na fronteira entre linhas, persiste o cache (flush) e "
             "sai com código 0. Útil para interromper execuções longas de forma limpa.",
    )

    args = parser.parse_args()

    # CSU01 — valida chave de API (RNF02)
    if not args.api_key:
        parser.error(
            "Chave da API não encontrada.\n"
            "Use --api-key ou exporte: export SHODAN_API_KEY='sua_chave'"
        )

    api = init_api(args.api_key)

    if args.info:
        info_mode(api)

    elif args.demo:
        demo_mode(api, args.demo, dump_json=args.json)

    else:
        # Modo pipeline padrão
        cache = ShodanCache(args.cache_file, save_every=args.cache_save_every)
        atexit.register(cache.flush)
        process_pipeline(
            api,
            cache,
            rate_limit=args.rate_limit,
            stop_file=args.stop_file,
        )


if __name__ == "__main__":
    main()
