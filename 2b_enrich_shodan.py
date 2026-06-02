#!/usr/bin/python3
# coding=utf-8
#
# Enriquece o CSV com dados do Shodan para IPs de origem.
# Lê output.csv.enriched.gz, adiciona colunas Shodan, gera output.csv.shodan.gz
#
# Uso:
#   zcat output.csv.enriched.gz | python3 2b_enrich_shodan.py | gzip > output.csv.shodan.gz
#
# Colunas adicionadas ao CSV (campos 18-24):
#   shodan_org, shodan_isp, shodan_ports, shodan_vulns,
#   shodan_tags, shodan_os, shodan_hostnames

import os
import sys
import time
import sqlite3
import shodan

# ── Configuração ──────────────────────────────────────────────────────────────

from dotenv import load_dotenv
load_dotenv()
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")

if not SHODAN_API_KEY:
    print("[ERRO]: A variável SHODAN_API_KEY não foi definida no arquivo .env", file=sys.stderr)
    sys.exit(1)

# Arquivo de cache persistente (SQLite). Evita re-consultar IPs já vistos.
CACHE_DB = "shodan_cache.db"

# Delay entre requisições para respeitar rate limit (1 req/s no plano gratuito).
# Aumente para 1.1 se receber erros 429.
REQUEST_DELAY = 1.1

# Campos a extrair do Shodan. Ajuste conforme interesse da pesquisa.
EMPTY_SHODAN = {
    "org":       "Unknown",
    "isp":       "Unknown",
    "ports":     "",        # ex: "22,80,443"
    "vulns":     "",        # ex: "CVE-2021-44228,CVE-2022-0001"
    "tags":      "",        # ex: "honeypot,tor"
    "os":        "Unknown",
    "hostnames": "",        # ex: "host.example.com"
}

# ── Cache SQLite ──────────────────────────────────────────────────────────────

def init_cache(db_path):
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS shodan_cache (
            ip          TEXT PRIMARY KEY,
            org         TEXT,
            isp         TEXT,
            ports       TEXT,
            vulns       TEXT,
            tags        TEXT,
            os          TEXT,
            hostnames   TEXT,
            queried_at  TEXT DEFAULT (datetime('now'))
        )
    """)
    conn.commit()
    return conn

def cache_get(conn, ip):
    row = conn.execute(
        "SELECT org, isp, ports, vulns, tags, os, hostnames FROM shodan_cache WHERE ip = ?",
        (ip,)
    ).fetchone()
    if row:
        return {
            "org":       row[0],
            "isp":       row[1],
            "ports":     row[2],
            "vulns":     row[3],
            "tags":      row[4],
            "os":        row[5],
            "hostnames": row[6],
        }
    return None

def cache_set(conn, ip, data):
    conn.execute("""
        INSERT OR REPLACE INTO shodan_cache
            (ip, org, isp, ports, vulns, tags, os, hostnames)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        ip,
        data["org"],
        data["isp"],
        data["ports"],
        data["vulns"],
        data["tags"],
        data["os"],
        data["hostnames"],
    ))
    conn.commit()

# ── Consulta Shodan ───────────────────────────────────────────────────────────

def query_shodan(api, ip):
    """
    Consulta o Shodan para um IP. Retorna dict com campos padronizados.
    Em caso de erro (IP não indexado, rate limit, etc.), retorna EMPTY_SHODAN.
    """
    try:
        host = api.host(ip)
        ports    = ",".join(str(p) for p in sorted(host.get("ports", [])))
        vulns    = ",".join(host.get("vulns", {}).keys())
        tags     = ",".join(host.get("tags", []))
        hostnames = ",".join(host.get("hostnames", []))
        os_      = host.get("os") or "Unknown"
        org      = host.get("org") or "Unknown"
        isp      = host.get("isp") or "Unknown"
        return {
            "org":       org,
            "isp":       isp,
            "ports":     ports,
            "vulns":     vulns,
            "tags":      tags,
            "os":        os_,
            "hostnames": hostnames,
        }
    except shodan.APIError as e:
        # "No information available for that IP" é o caso mais comum — não é erro crítico.
        if "No information" not in str(e):
            print(f"[SHODAN] APIError para {ip}: {e}", file=sys.stderr)
        return dict(EMPTY_SHODAN)
    except Exception as e:
        print(f"[SHODAN] Erro inesperado para {ip}: {e}", file=sys.stderr)
        return dict(EMPTY_SHODAN)

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    api  = shodan.Shodan(SHODAN_API_KEY)
    conn = init_cache(CACHE_DB)

    stats = {"hit": 0, "miss": 0, "lines": 0, "errors": 0}

    for rawline in sys.stdin:
        line = rawline.rstrip()
        fields = line.split(',')

        # Valida número de campos esperados do pipeline anterior (18 campos: índices 0-17)
        if len(fields) < 18:
            print(f"[SKIP] Linha com {len(fields)} campos: {line[:80]}", file=sys.stderr)
            stats["errors"] += 1
            continue

        ipsrc = fields[1]

        # Tenta cache antes de chamar a API
        cached = cache_get(conn, ipsrc)
        if cached:
            stats["hit"] += 1
            shodan_data = cached
        else:
            stats["miss"] += 1
            time.sleep(REQUEST_DELAY)
            shodan_data = query_shodan(api, ipsrc)
            cache_set(conn, ipsrc, shodan_data)

        # Monta linha de saída: campos originais + 7 campos Shodan
        output = (
            line + ","
            + shodan_data["org"]       + ","
            + shodan_data["isp"]       + ","
            + shodan_data["ports"]     + ","
            + shodan_data["vulns"]     + ","
            + shodan_data["tags"]      + ","
            + shodan_data["os"]        + ","
            + shodan_data["hostnames"]
        )
        print(output)

        stats["lines"] += 1
        if stats["lines"] % 10000 == 0:
            print(
                f"[PROGRESS] {stats['lines']} linhas | "
                f"cache hit: {stats['hit']} | miss: {stats['miss']}",
                file=sys.stderr
            )

    conn.close()
    print(
        f"[DONE] Total: {stats['lines']} linhas | "
        f"cache hit: {stats['hit']} | miss: {stats['miss']} | erros: {stats['errors']}",
        file=sys.stderr
    )

if __name__ == "__main__":
    main()

