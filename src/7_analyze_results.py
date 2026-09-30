#!/usr/bin/env python3
"""
Análise de resultados do pipeline enriquecido (28 colunas).

Gera distribuições estatísticas a partir dos metadados Shodan:
  - Distribuição de dispositivos por OS detectado
  - Ranking de organizações e de ISPs com mais IPs de origem
  - Portas abertas mais comuns e CVEs associados a essas portas
  - Ganho informacional (`ganho_shodan`): quantos IPs enriquecidos têm cada
    metadado adicionado pelo Shodan (org, ISP, ASN, OS, portas, CPEs, CVEs,
    tags, hostnames) — campos inexistentes no ETL original
  - Cobertura do enriquecimento Shodan (`comparacao_pipeline`, CSV + terminal)
  - Distribuição geográfica de origem (país) cruzada com o OS detectado

Por padrão, os rankings (OS/org/ISP) omitem os IPs não enriquecidos (sem
registro / não consultados), usando o cache Shodan (found=True) como fonte de
verdade. Use --incluir-nao-enriquecidos para restaurar o comportamento antigo
(mostra "Sem registro" e as três categorias de cobertura).

Como todas as análises contam IPs únicos de origem, a entrada é deduplicada por
ip.src durante a leitura — o uso de memória fica proporcional ao número de IPs
únicos (não ao de pacotes). Linhas com número de campos diferente de 28 são
ignoradas (campos com vírgula embutida).

Uso:
  zcat output.shodan.csv.gz | python3 7_analyze_results.py \
      --original-csv output.enriched.csv.gz --output-dir .
"""

import sys
import os

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

import argparse
import gzip
import json

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

# Metadados adicionados pela etapa 6 (Shodan) — inexistentes no ETL original.
# Usados na análise de ganho informacional.
CAMPOS_GANHO = [
    ("shodan_org", "Organização"),
    ("shodan_isp", "ISP"),
    ("shodan_asn", "ASN"),
    ("shodan_os", "Sistema operacional"),
    ("shodan_open_ports", "Portas abertas"),
    ("shodan_cpes", "CPEs"),
    ("shodan_cves", "CVEs"),
    ("shodan_tags", "Tags"),
    ("shodan_hostnames", "Hostnames"),
]


def read_csv_from_stdin():
    """Lê CSV do stdin e retorna DataFrame com as 28 colunas esperadas.

    Todas as análises contam IPs únicos de origem; por isso mantém apenas a
    primeira linha de cada IP de origem (dedup), o que mantém o consumo de
    memória proporcional ao número de IPs únicos — e não ao número de pacotes
    (que pode ser centenas de milhões de linhas). O resultado das análises é
    idêntico ao da leitura linha a linha.
    """
    lines = []
    vistos = set()
    total = 0
    malformadas = 0
    for raw in sys.stdin:
        total += 1
        line = raw.rstrip("\n\r")
        # extrai o IP de origem sem fatiar a linha inteira (caminho rápido)
        partes = line.split(",", 2)
        if len(partes) < 3:
            malformadas += 1
            continue
        ip_src = partes[1]
        if ip_src in vistos:
            continue
        fields = line.split(",")
        if len(fields) != 28:
            malformadas += 1
            continue
        vistos.add(ip_src)
        lines.append(fields)

    if not lines:
        print("Nenhuma linha válida lida.", file=sys.stderr)
        sys.exit(1)

    print(
        f"Linhas lidas: {total} | IPs únicos de origem mantidos: {len(lines)} | "
        f"linhas malformadas ignoradas: {malformadas}",
        file=sys.stderr,
    )
    return pd.DataFrame(lines, columns=COL_NAMES)


def contagem_por_campo(df, campo, drop_empty=False):
    """
    Conta IPs únicos de origem por valor de um campo (coluna) do CSV.
    Por padrão, valores vazios (IP sem dados Shodan) são agrupados em
    'Sem registro'. Com drop_empty=True, linhas com o campo vazio são
    descartadas (não geram a categoria 'Sem registro').
    """
    sub = df[["ip_src", campo]].copy()
    if drop_empty:
        sub = sub[sub[campo].notna() & (sub[campo] != "")]

    agg = (
        sub.groupby(campo)["ip_src"]
        .nunique()
        .reset_index()
        .rename(columns={"ip_src": "ips_unicos"})
    )
    if not drop_empty:
        agg[campo] = agg[campo].replace("", SEM_REGISTRO)
    agg = agg.sort_values("ips_unicos", ascending=False).reset_index(drop=True)

    total = int(agg["ips_unicos"].sum())
    agg["percentual"] = (agg["ips_unicos"] / total * 100).round(2) if total else 0
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
    if dados.empty:
        print(f"Sem dados para plotar: {output_path}", file=sys.stderr)
        return

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


def imprimir_contagem(df, campo, titulo, limite=20):
    """Exibe no stderr a tabela de contagem (limitada a `limite` linhas)."""
    print(f"\n--- {titulo} ---", file=sys.stderr)
    for _, row in df.head(limite).iterrows():
        print(
            f"  {str(row[campo]):<40} {int(row['ips_unicos']):>6}  "
            f"({row['percentual']}%)",
            file=sys.stderr,
        )
    if len(df) > limite:
        print(f"  ... e mais {len(df) - limite} categorias (ver CSV)",
              file=sys.stderr)


def salvar_analise_por_campo(df, campo, base_nome, titulo, xlabel, output_dir,
                              drop_empty=False):
    """Salva CSV + PNG + imprime resumo de uma contagem por campo."""
    agg = contagem_por_campo(df, campo, drop_empty=drop_empty)

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

    Extrai apenas o segundo campo (ip.src) sem fatiar a linha inteira, para
    aguentar arquivos com centenas de milhões de linhas.
    """
    abertura = gzip.open if caminho_csv.endswith(".gz") else open
    ips = set()
    with abertura(caminho_csv, "rt", encoding="utf-8") as f:
        for raw in f:
            line = raw.rstrip("\n\r")
            i = line.find(",")
            if i == -1:
                continue
            j = line.find(",", i + 1)
            ip = line[i + 1:j] if j != -1 else line[i + 1:]
            if ip:
                ips.add(ip)
    return ips


def ler_cache_shodan(caminho_cache):
    """
    Lê o cache Shodan (JSON por IP) e retorna o dict {ip: registro}.
    Retorna {} quando o caminho é None, inexistente ou ilegível.
    """
    if not caminho_cache or not os.path.exists(caminho_cache):
        return {}
    try:
        with open(caminho_cache, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def analisar_comparacao(df, caminho_original, caminho_cache, output_dir, detalhado=False):
    """
    Mede a cobertura do enriquecimento Shodan usando o cache como fonte de
    verdade.

    No modo padrão (detalhado=False), compara as duas coletas:
      - "Com Shodan (enriquecidos)"    : IPs únicos de origem com dados no cache
                                         (found=True)
      - "Sem Shodan (não enriquecidos)": demais IPs (sem dados + não consultados)

    Com detalhado=True, separa em três categorias:
      - Consultados com dados no Shodan   (presentes no cache com found=True)
      - Consultados sem dados no Shodan   (presentes no cache com found=False)
      - Não consultados                   (ausentes do cache)
    """
    if caminho_original:
        ips_originais = ler_ips_originais(caminho_original)
    else:
        ips_originais = set(df["ip_src"].unique())

    cache = ler_cache_shodan(caminho_cache)
    cache_ips = set(cache.keys()) & ips_originais

    com_dados = {ip for ip in cache_ips if cache[ip].get("found")}
    sem_dados = cache_ips - com_dados
    nao_consultados = ips_originais - cache_ips

    total_original = len(ips_originais)

    def pct(n):
        return round(n / total_original * 100, 2) if total_original else None

    if detalhado:
        resumo_df = pd.DataFrame([
            {
                "categoria": "Consultados com dados no Shodan",
                "ips_unicos": len(com_dados),
                "pct_original": pct(len(com_dados)),
            },
            {
                "categoria": "Consultados sem dados no Shodan",
                "ips_unicos": len(sem_dados),
                "pct_original": pct(len(sem_dados)),
            },
            {
                "categoria": "Não consultados",
                "ips_unicos": len(nao_consultados),
                "pct_original": pct(len(nao_consultados)),
            },
        ])
    else:
        nao_enriquecidos = total_original - len(com_dados)
        resumo_df = pd.DataFrame([
            {
                "categoria": "Com Shodan (enriquecidos)",
                "ips_unicos": len(com_dados),
                "pct_original": pct(len(com_dados)),
            },
            {
                "categoria": "Sem Shodan (não enriquecidos)",
                "ips_unicos": nao_enriquecidos,
                "pct_original": pct(nao_enriquecidos),
            },
        ])

    csv_path = os.path.join(output_dir, "comparacao_pipeline.csv")
    resumo_df.to_csv(csv_path, index=False)
    print(f"Tabela salva: {csv_path}", file=sys.stderr)

    print("\n--- Cobertura do enriquecimento Shodan ---", file=sys.stderr)
    print(f"  IPs únicos de origem (universo):      {total_original}",
          file=sys.stderr)
    print(f"  Com Shodan (enriquecidos):            {len(com_dados)}",
          file=sys.stderr)
    print(f"  Sem Shodan (não enriquecidos):        {total_original - len(com_dados)}",
          file=sys.stderr)
    if detalhado:
        print(f"  Consultados sem dados no Shodan:      {len(sem_dados)}",
              file=sys.stderr)
        print(f"  Não consultados:                      {len(nao_consultados)}",
              file=sys.stderr)


def analisar_ganho(df, output_dir):
    """
    Mostra o ganho informacional do Shodan: para cada metadado adicionado pela
    etapa 6 (inexistente no ETL original), conta quantos IPs de origem
    enriquecidos possuem o campo preenchido. Gera ganho_shodan.{csv,png}.
    """
    total = df["ip_src"].nunique()
    linhas = []
    for campo, nome in CAMPOS_GANHO:
        n = df.loc[df[campo].notna() & (df[campo] != ""), "ip_src"].nunique()
        linhas.append({
            "metadado": nome,
            "ips_unicos": int(n),
            "percentual": round(n / total * 100, 2) if total else 0,
        })
    agg = (
        pd.DataFrame(linhas)
        .sort_values("ips_unicos", ascending=False)
        .reset_index(drop=True)
    )

    csv_path = os.path.join(output_dir, "ganho_shodan.csv")
    agg.to_csv(csv_path, index=False)
    print(f"Tabela salva: {csv_path}", file=sys.stderr)

    png_path = os.path.join(output_dir, "ganho_shodan.png")
    plot_barras(
        agg, "metadado",
        f"Ganho do enriquecimento Shodan — IPs de origem com cada metadado "
        f"({total} enriquecidos)",
        "Número de IPs únicos de origem", png_path, top=len(CAMPOS_GANHO),
    )

    print("\n--- Ganho informacional do Shodan ---", file=sys.stderr)
    if total:
        for _, row in agg.iterrows():
            print(f"  {row['metadado']:<25} {int(row['ips_unicos']):>6}  "
                  f"({row['percentual']}%)", file=sys.stderr)
    else:
        print("  (nenhum IP enriquecido no cache)", file=sys.stderr)


def analisar_geo_os(df, output_dir):
    """
    Distribuição geográfica de origem cruzada com o OS detectado.
    Conta IPs únicos de origem por combinação país × OS e salva em
    geo_os_cross.csv.
    """
    sub = df[["ip_src", "src_country", "src_lat", "src_lon", "shodan_os"]].copy()
    sub["src_lat"] = pd.to_numeric(sub["src_lat"], errors="coerce")
    sub["src_lon"] = pd.to_numeric(sub["src_lon"], errors="coerce")

    sub = sub[sub["src_lat"].between(-90, 90) & sub["src_lon"].between(-180, 180)]
    sub = sub.dropna(subset=["src_lat", "src_lon"])
    sub = sub.drop_duplicates(subset=["ip_src"])
    sub["shodan_os"] = sub["shodan_os"].fillna("").replace("", SEM_REGISTRO)
    sub["src_country"] = sub["src_country"].fillna("").replace("", "País desconhecido")

    cruz = (
        sub.groupby(["src_country", "shodan_os"])["ip_src"]
        .nunique()
        .reset_index(name="ips_unicos")
    )
    cruz_csv = cruz.sort_values("ips_unicos", ascending=False)
    csv_path = os.path.join(output_dir, "geo_os_cross.csv")
    cruz_csv.to_csv(csv_path, index=False)
    print(f"Tabela salva: {csv_path}", file=sys.stderr)

    print("\n--- Distribuição geográfica (país) × OS ---", file=sys.stderr)
    for _, row in cruz_csv.head(20).iterrows():
        print(f"  {row['src_country']:<30} {row['shodan_os']:<20} "
              f"{int(row['ips_unicos'])} IPs", file=sys.stderr)
    if len(cruz_csv) > 20:
        print(f"  ... e mais {len(cruz_csv) - 20} combinações (ver {csv_path})",
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
            "CSV do pipeline original (18 colunas, saída da etapa 2), usado como "
            "universo de IPs de origem na comparação de cobertura. Se omitido, a "
            "base considerada é a dos IPs presentes no próprio CSV de entrada."
        ),
    )
    parser.add_argument(
        "--cache-file",
        default=os.path.join(PROJECT_ROOT, "logs", "shodan_cache.json"),
        metavar="ARQUIVO",
        help=(
            "Cache Shodan (JSON por IP) usado para medir a cobertura real do "
            "enriquecimento (padrão: logs/shodan_cache.json)."
        ),
    )
    parser.add_argument(
        "--incluir-nao-enriquecidos",
        action="store_true",
        help=(
            "Restaura o comportamento antigo: mantém a categoria 'Sem registro' "
            "nos rankings (OS/org/ISP) e as três categorias de cobertura (com "
            "dados / sem dados / não consultados) no comparacao_pipeline. Por "
            "padrão, esses dados não coletados são omitidos."
        ),
    )
    args = parser.parse_args()

    output_dir = args.output_dir
    os.makedirs(output_dir, exist_ok=True)

    df = read_csv_from_stdin()
    print(f"Linhas processadas: {len(df)}", file=sys.stderr)
    print(f"IPs únicos de origem: {df['ip_src'].nunique()}", file=sys.stderr)

    cache = ler_cache_shodan(args.cache_file)

    if args.original_csv:
        universo = ler_ips_originais(args.original_csv)
    else:
        universo = set(df["ip_src"].unique())

    cache_ips = set(cache.keys()) & universo
    com_dados = {ip for ip in cache_ips if cache[ip].get("found")}

    filtrar = not args.incluir_nao_enriquecidos
    if filtrar and not com_dados:
        print(
            "AVISO: nenhum IP enriquecido encontrado no cache — "
            "mantendo o comportamento antigo (sem filtragem).",
            file=sys.stderr,
        )
        filtrar = False

    df_analise = df[df["ip_src"].isin(com_dados)] if filtrar else df
    if filtrar:
        print(
            f"Filtrando análise para {len(com_dados)} IPs enriquecidos "
            f"(found=True no cache).",
            file=sys.stderr,
        )

    salvar_analise_por_campo(
        df_analise, "shodan_os", "os_distribution",
        "Distribuição de Dispositivos por OS Detectado (Shodan)",
        "Número de IPs únicos de origem", output_dir,
        drop_empty=filtrar,
    )

    salvar_analise_por_campo(
        df_analise, "shodan_org", "org_ranking",
        "Ranking de Organizações por IPs de Origem (Shodan)",
        "Número de IPs únicos de origem", output_dir,
        drop_empty=filtrar,
    )

    salvar_analise_por_campo(
        df_analise, "shodan_isp", "isp_ranking",
        "Ranking de ISPs por IPs de Origem (Shodan)",
        "Número de IPs únicos de origem", output_dir,
        drop_empty=filtrar,
    )

    top_portas = ranking_portas(df_analise)
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

        port_cves = cves_por_porta(df_analise, top_portas)
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

    analisar_comparacao(
        df, args.original_csv, args.cache_file, output_dir,
        detalhado=args.incluir_nao_enriquecidos,
    )
    analisar_ganho(df[df["ip_src"].isin(com_dados)], output_dir)
    analisar_geo_os(df_analise, output_dir)


if __name__ == "__main__":
    main()
