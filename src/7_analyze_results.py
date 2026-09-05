#!/usr/bin/env python3
"""
Análise de resultados do pipeline enriquecido (28 colunas).

Gera distribuições estatísticas a partir dos metadados Shodan:
  - Distribuição de dispositivos por OS detectado
  - Ranking de organizações e de ISPs com mais IPs de origem
  - Portas abertas mais comuns e CVEs associados a essas portas
  - Comparação pipeline original (18 colunas) vs estendido (28 colunas):
    quantos IPs de origem ganharam metadados técnicos do Shodan

Uso:
  zcat output.shodan.csv.gz | python3 7_analyze_results.py \
      --original-csv output.enriched.csv.gz --output-dir .
"""

import sys
import os

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

import argparse
import gzip

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

SEM_REGISTRO = "Sem registro"

SHODAN_FIELD_COLS = [
    "shodan_org", "shodan_isp", "shodan_asn", "shodan_os",
    "shodan_open_ports", "shodan_cpes", "shodan_cves",
    "shodan_tags", "shodan_hostnames", "shodan_last_seen",
]


def read_csv_from_stdin():
    """Lê CSV do stdin e retorna DataFrame com as 28 colunas esperadas."""
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

    return pd.DataFrame(lines, columns=COL_NAMES)


def contagem_por_campo(df, campo):
    """
    Conta IPs únicos de origem por valor de um campo (coluna) do CSV.
    Valores vazios (IP sem dados Shodan) são agrupados em 'Sem registro'.
    """
    agg = (
        df.groupby(campo)["ip_src"]
        .nunique()
        .reset_index()
        .rename(columns={"ip_src": "ips_unicos"})
    )
    agg[campo] = agg[campo].replace("", SEM_REGISTRO)
    agg = agg.sort_values("ips_unicos", ascending=False).reset_index(drop=True)

    total = int(agg["ips_unicos"].sum())
    agg["percentual"] = (agg["ips_unicos"] / total * 100).round(2)
    return agg


def ranking_portas(df):
    """
    Conta IPs únicos de origem por porta aberta reportada pelo Shodan
    (campo shodan_open_ports, lista separada por '|').
    """
    sub = df[["ip_src", "shodan_open_ports"]].copy()
    sub = sub[sub["shodan_open_ports"].notna() & (sub["shodan_open_ports"] != "")]
    sub["porta"] = sub["shodan_open_ports"].str.split("|")
    flat = sub.explode("porta")
    flat = flat[flat["porta"].astype(str).str.strip() != ""]

    agg = (
        flat.groupby("porta")["ip_src"]
        .nunique()
        .reset_index()
        .rename(columns={"ip_src": "ips_unicos"})
    )
    agg = agg.sort_values("ips_unicos", ascending=False).reset_index(drop=True)

    total = int(agg["ips_unicos"].sum())
    agg["percentual"] = (agg["ips_unicos"] / total * 100).round(2)
    return agg


def cves_por_porta(df, top_portas, limite=10):
    """
    Para as portas mais comuns (limite), associa os CVEs dos IPs que as possuem.
    Como o Shodan agrega CVEs por host (e não por serviço), a associação é
    aproximada: CVEs presentes em IPs que exibem a porta aberta.
    """
    pp = df[["ip_src", "shodan_open_ports"]].copy()
    pp = pp[pp["shodan_open_ports"].notna() & (pp["shodan_open_ports"] != "")]
    pp["porta"] = pp["shodan_open_ports"].str.split("|")
    pp = pp.explode("porta")
    pp = pp[pp["porta"].astype(str).str.strip() != ""]
    pp = pp[["ip_src", "porta"]].drop_duplicates()

    pc = df[["ip_src", "shodan_cves"]].copy()
    pc = pc[pc["shodan_cves"].notna() & (pc["shodan_cves"] != "")]
    pc["cve"] = pc["shodan_cves"].str.split("|")
    pc = pc.explode("cve")
    pc = pc[pc["cve"].astype(str).str.strip() != ""]
    pc = pc[["ip_src", "cve"]].drop_duplicates()

    sel = list(top_portas["porta"].head(limite))
    pp = pp[pp["porta"].isin(sel)]
    merged = pp.merge(pc, on="ip_src", how="inner")

    if merged.empty:
        return pd.DataFrame(columns=["porta", "cve", "ips_afetados"])

    agg = (
        merged.groupby(["porta", "cve"])
        .size()
        .reset_index(name="ips_afetados")
    )
    ordem = {p: i for i, p in enumerate(sel)}
    agg["_ordem"] = agg["porta"].map(ordem)
    agg = (
        agg.sort_values(["_ordem", "ips_afetados"], ascending=[True, False])
        .drop(columns="_ordem")
        .reset_index(drop=True)
    )
    return agg


def plot_barras(df, label_col, titulo, xlabel, output_path, top=15):
    """Gera gráfico de barras horizontais (top N) para uma contagem por campo."""
    dados = df.head(top).iloc[::-1].reset_index(drop=True)

    labels = dados[label_col].astype(str)
    values = dados["ips_unicos"].astype(int)
    colors = ["#95a5a6" if l == SEM_REGISTRO else "#2ecc71" for l in labels]

    fig, ax = plt.subplots(figsize=(10, 6))
    bars = ax.barh(labels, values, color=colors)
    ax.set_xlabel(xlabel)
    ax.set_ylabel(label_col)
    ax.set_title(titulo)

    for bar, val in zip(bars, values):
        ax.text(
            bar.get_width() + max(values) * 0.01,
            bar.get_y() + bar.get_height() / 2,
            str(val),
            va="center",
            fontsize=9,
        )
    ax.set_xlim(0, max(values) * 1.1)

    plt.tight_layout()
    plt.savefig(output_path, dpi=150)
    plt.close()
    print(f"Gráfico salvo: {output_path}", file=sys.stderr)


def imprimir_contagem(df, campo, titulo):
    """Exibe no stderr a tabela de contagem gerada."""
    print(f"\n--- {titulo} ---", file=sys.stderr)
    for _, row in df.iterrows():
        print(
            f"  {str(row[campo]):<40} {int(row['ips_unicos']):>6}  "
            f"({row['percentual']}%)",
            file=sys.stderr,
        )


def salvar_analise_por_campo(df, campo, base_nome, titulo, xlabel, output_dir):
    """Salva CSV + PNG + imprime resumo de uma contagem por campo."""
    agg = contagem_por_campo(df, campo)

    csv_path = os.path.join(output_dir, f"{base_nome}.csv")
    agg.to_csv(csv_path, index=False)
    print(f"Tabela salva: {csv_path}", file=sys.stderr)

    png_path = os.path.join(output_dir, f"{base_nome}.png")
    plot_barras(agg, campo, titulo, xlabel, png_path)

    imprimir_contagem(agg, campo, titulo)
    return agg


def ler_ips_originais(caminho_csv):
    """
    Lê um CSV (18 colunas, .gz ou plano) e retorna o conjunto de IPs de origem.
    """
    abertura = gzip.open if caminho_csv.endswith(".gz") else open
    ips = set()
    with abertura(caminho_csv, "rt", encoding="utf-8") as f:
        for raw in f:
            fields = raw.rstrip("\n\r").split(",")
            if len(fields) >= 2 and fields[1]:
                ips.add(fields[1])
    return ips


def ips_com_metadados_shodan(df):
    """Conjunto de IPs de origem com ao menos um campo Shodan preenchido."""
    sub = df[SHODAN_FIELD_COLS].fillna("") != ""
    tem_algum = sub.any(axis=1)
    return set(df.loc[tem_algum, "ip_src"].unique())


def plot_comparacao(resumo, output_path):
    """Gráfico de barras horizontais com o resumo da comparação 18 vs 28."""
    fig, ax = plt.subplots(figsize=(10, 6))

    categorias = list(resumo.keys())
    valores = list(resumo.values())
    cores = [
        "#3498db",      # total original
        "#2ecc71",      # ganharam metadados
        "#95a5a6",      # sem dados Shodan
        "#f39c12",      # ainda não consultados
    ]

    bars = ax.barh(categorias[::-1], valores[::-1], color=cores[::-1])
    ax.set_xlabel("Número de IPs únicos de origem")
    ax.set_title("Comparação: Pipeline Original (18 colunas) vs Estendido (28 colunas)")

    for bar, val in zip(bars, valores[::-1]):
        ax.text(bar.get_width() + max(valores) * 0.01,
                bar.get_y() + bar.get_height() / 2,
                str(val), va="center", fontsize=9)
    ax.set_xlim(0, max(valores) * 1.1)

    plt.tight_layout()
    plt.savefig(output_path, dpi=150)
    plt.close()
    print(f"Gráfico salvo: {output_path}", file=sys.stderr)


def analisar_comparacao(df, caminho_original, output_dir):
    """
    Compara o pipeline original (18 colunas) com o estendido (28 colunas):
    quantos IPs únicos de origem ganharam metadados técnicos do Shodan.
    """
    ips_processados = set(df["ip_src"].unique())

    if caminho_original:
        ips_originais = ler_ips_originais(caminho_original)
    else:
        ips_originais = ips_processados

    ganharam = ips_com_metadados_shodan(df)
    sem_dados = ips_processados - ganharam
    nao_consultados = ips_originais - ips_processados

    total_original = len(ips_originais)
    total_processados = len(ips_processados)

    def pct(n, base):
        return round(n / base * 100, 2) if base else None

    resumo_df = pd.DataFrame([
        {
            "categoria": "Pipeline original (18 col)",
            "ips_unicos": total_original,
            "pct_original": 100.0,
            "pct_processados": None,
        },
        {
            "categoria": "IPs processados pela etapa 6 (28 col)",
            "ips_unicos": total_processados,
            "pct_original": pct(total_processados, total_original),
            "pct_processados": 100.0,
        },
        {
            "categoria": "Ganharam metadados técnicos Shodan",
            "ips_unicos": len(ganharam),
            "pct_original": pct(len(ganharam), total_original),
            "pct_processados": pct(len(ganharam), total_processados),
        },
        {
            "categoria": "Sem dados no Shodan",
            "ips_unicos": len(sem_dados),
            "pct_original": pct(len(sem_dados), total_original),
            "pct_processados": pct(len(sem_dados), total_processados),
        },
        {
            "categoria": "Ainda não consultados (sem Shodan)",
            "ips_unicos": len(nao_consultados),
            "pct_original": pct(len(nao_consultados), total_original),
            "pct_processados": None,
        },
    ])

    csv_path = os.path.join(output_dir, "comparacao_pipeline.csv")
    resumo_df.to_csv(csv_path, index=False)
    print(f"Tabela salva: {csv_path}", file=sys.stderr)

    resumo_plot = {
        "Pipeline original (18 col)": total_original,
        "Ganharam metadados técnicos Shodan": len(ganharam),
        "Sem dados no Shodan": len(sem_dados),
        "Ainda não consultados (sem Shodan)": len(nao_consultados),
    }
    png_path = os.path.join(output_dir, "comparacao_pipeline.png")
    plot_comparacao(resumo_plot, png_path)

    print("\n--- Comparação 18 vs 28 colunas ---", file=sys.stderr)
    print(f"  IPs únicos no pipeline original (18 col): {total_original}",
          file=sys.stderr)
    print(f"  IPs processados pela etapa 6 (28 col):    {total_processados}",
          file=sys.stderr)
    print(f"  IPs que ganharam metadados Shodan:         {len(ganharam)}",
          file=sys.stderr)
    print(f"  IPs sem dados no Shodan:                   {len(sem_dados)}",
          file=sys.stderr)
    print(f"  IPs ainda não consultados:                 {len(nao_consultados)}",
          file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(
        description="Análise de resultados do pipeline enriquecido (28 colunas).",
    )
    parser.add_argument(
        "--output-dir",
        default=".",
        help="Diretório de saída para os artefatos gerados (padrão: diretório atual)",
    )
    parser.add_argument(
        "--original-csv",
        default=None,
        metavar="ARQUIVO",
        help=(
            "CSV do pipeline original (18 colunas, saída da etapa 2), usado na "
            "comparação 18 vs 28. Se omitido, a base considerada é a dos IPs "
            "presentes no próprio CSV de entrada."
        ),
    )
    args = parser.parse_args()

    output_dir = args.output_dir
    os.makedirs(output_dir, exist_ok=True)

    df = read_csv_from_stdin()
    print(f"Linhas processadas: {len(df)}", file=sys.stderr)
    print(f"IPs únicos de origem: {df['ip_src'].nunique()}", file=sys.stderr)

    salvar_analise_por_campo(
        df, "shodan_os", "os_distribution",
        "Distribuição de Dispositivos por OS Detectado (Shodan)",
        "Número de IPs únicos de origem", output_dir,
    )

    salvar_analise_por_campo(
        df, "shodan_org", "org_ranking",
        "Ranking de Organizações por IPs de Origem (Shodan)",
        "Número de IPs únicos de origem", output_dir,
    )

    salvar_analise_por_campo(
        df, "shodan_isp", "isp_ranking",
        "Ranking de ISPs por IPs de Origem (Shodan)",
        "Número de IPs únicos de origem", output_dir,
    )

    top_portas = ranking_portas(df)
    if top_portas.empty:
        print("Nenhuma porta aberta reportada — pulando análise de portas.",
              file=sys.stderr)
    else:
        csv_path = os.path.join(output_dir, "top_ports.csv")
        top_portas.to_csv(csv_path, index=False)
        print(f"Tabela salva: {csv_path}", file=sys.stderr)

        png_path = os.path.join(output_dir, "top_ports.png")
        plot_barras(top_portas, "porta",
                    "Portas Abertas Mais Comuns (Shodan)",
                    "Número de IPs únicos de origem", png_path)

        imprimir_contagem(top_portas, "porta", "Portas abertas mais comuns")

        port_cves = cves_por_porta(df, top_portas)
        csv_cves = os.path.join(output_dir, "port_cves.csv")
        port_cves.to_csv(csv_cves, index=False)
        print(f"Tabela salva: {csv_cves}", file=sys.stderr)

        if port_cves.empty:
            print("Nenhum CVE associado às portas mais comuns.", file=sys.stderr)
        else:
            print("\n--- CVEs associados às portas mais comuns (amostra) ---",
                  file=sys.stderr)
            for _, row in port_cves.head(20).iterrows():
                print(
                    f"  porta {str(row['porta']):<6} {row['cve']:<20} "
                    f"({row['ips_afetados']} IPs)",
                    file=sys.stderr,
                )
            if len(port_cves) > 20:
                print(
                    f"  ... e mais {len(port_cves) - 20} associações "
                    f"(ver {csv_cves})",
                    file=sys.stderr,
                )

    analisar_comparacao(df, args.original_csv, output_dir)


if __name__ == "__main__":
    main()
