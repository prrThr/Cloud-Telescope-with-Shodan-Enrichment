#!/usr/bin/env python3
"""
Análise de resultados do pipeline enriquecido (28 colunas).

Gera distribuição de dispositivos por OS detectado pelo Shodan.

Uso:
  zcat output.shodan.csv.gz | python3 7_analyze_results.py --output-dir .
"""

import sys
import os

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

import argparse
import gzip
from collections import Counter

import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


COL_NAMES = [
    "time", "ip_src", "ip_dst", "tcp_dstport", "tcp_flags",
    "udp_dstport", "icmp_type",
    "src_iso", "src_country", "src_city", "src_lat", "src_lon",
    "dst_iso", "dst_country", "dst_city", "dst_lat", "dst_lon",
    "aws_region",
    "shodan_org", "shodan_isp", "shodan_asn", "shodan_os",
    "shodan_open_ports", "shodan_cpes", "shodan_cves",
    "shodan_tags", "shodan_hostnames", "shodan_last_seen",
]

SHODAN_OS_IDX = 21


def read_csv_from_stdin():
    """Lê CSV comprimido do stdin e retorna DataFrame."""
    lines = []
    for raw in sys.stdin:
        line = raw.rstrip("\n\r")
        fields = line.split(",")
        if len(fields) < 28:
            continue
        lines.append(fields)

    if not lines:
        print("Nenhuma linha válida lida.", file=sys.stderr)
        sys.exit(1)

    df = pd.DataFrame(lines, columns=COL_NAMES)
    return df


def analyze_os_distribution(df):
    """
    Conta IPs únicos de origem por OS detectado.
    IPs com shodan_os vazio são classificados como 'Sem registro'.
    """
    ips_by_os = (
        df.groupby("shodan_os")["ip_src"]
        .nunique()
        .reset_index()
        .rename(columns={"ip_src": "ips_unicos"})
    )

    ips_by_os["shodan_os"] = ips_by_os["shodan_os"].replace("", "Sem registro")
    ips_by_os = ips_by_os.sort_values("ips_unicos", ascending=False).reset_index(drop=True)

    total = ips_by_os["ips_unicos"].sum()
    ips_by_os["percentual"] = (ips_by_os["ips_unicos"] / total * 100).round(2)

    return ips_by_os


def plot_os_distribution(ips_by_os, output_path):
    """Gera gráfico de barras da distribuição por OS."""
    fig, ax = plt.subplots(figsize=(10, 6))

    labels = ips_by_os["shodan_os"]
    values = ips_by_os["ips_unicos"]

    colors = ["#2ecc71" if l != "Sem registro" else "#95a5a6" for l in labels]

    bars = ax.barh(labels[::-1], values[::-1], color=colors[::-1])
    ax.set_xlabel("Número de IPs únicos de origem")
    ax.set_ylabel("Sistema Operacional")
    ax.set_title("Distribuição de Dispositivos por OS Detectado (Shodan)")

    for bar, val in zip(bars, values[::-1]):
        ax.text(bar.get_width() + max(values) * 0.01, bar.get_y() + bar.get_height() / 2,
                str(val), va="center", fontsize=9)

    plt.tight_layout()
    plt.savefig(output_path, dpi=150)
    plt.close()
    print(f"Gráfico salvo: {output_path}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(
        description="Análise de resultados do pipeline enriquecido (28 colunas).",
    )
    parser.add_argument(
        "--output-dir",
        default=".",
        help="Diretório de saída para os artefatos gerados (padrão: diretório atual)",
    )
    args = parser.parse_args()

    output_dir = args.output_dir
    os.makedirs(output_dir, exist_ok=True)

    df = read_csv_from_stdin()
    print(f"Linhas processadas: {len(df)}", file=sys.stderr)
    print(f"IPs únicos de origem: {df['ip_src'].nunique()}", file=sys.stderr)

    ips_by_os = analyze_os_distribution(df)

    csv_path = os.path.join(output_dir, "os_distribution.csv")
    ips_by_os.to_csv(csv_path, index=False)
    print(f"Tabela salva: {csv_path}", file=sys.stderr)

    png_path = os.path.join(output_dir, "os_distribution.png")
    plot_os_distribution(ips_by_os, png_path)

    print("\n--- Distribuição de OS ---", file=sys.stderr)
    for _, row in ips_by_os.iterrows():
        print(f"  {row['shodan_os']:<30} {row['ips_unicos']:>6}  ({row['percentual']}%)", file=sys.stderr)


if __name__ == "__main__":
    main()
