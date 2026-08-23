#!/bin/bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

DATASET="datasets/e1"
NUM_PCAPS=""
SHODAN_QUERIES=""
WITH_NEO4J=0
WITH_MYSQL=0

usage() {
cat <<EOF
Uso: other/full_etl.sh [opções]

Executa o pipeline principal por inteiro, criando um novo diretório de execução
em datasets/execucao_pipeline_<origem>_<data_hora>. O dataset de origem é apenas
lido (via links simbólicos) e execuções anteriores nunca são removidas ou alteradas.

Artefatos sempre gerados no diretório da execução:
  output.csv.gz            etapa 1 — extração tshark
  output.enriched.csv.gz   etapa 2 — enriquecimento GeoIP + AWS
  output.tex               etapa 3 — resumo LaTeX
  output.shodan.gz         etapa 6 — enriquecimento Shodan

Opções:
  -d, --dataset DIR        Diretório de origem das capturas (padrão: datasets/e1).
                           Com nomenclatura bruta (<região><az>-<IP>-<data>-<hora>),
                           a seleção usa a etapa 0 (estratificada por região); sem
                           nomenclatura elegível (ex.: agregados do datasets/e3), as
                           capturas são vinculadas por ordem alfabética do nome.
  -n, --num-pcaps N        Quantidade de capturas .pcap a utilizar
                           (padrão: todas as capturas da raiz do dataset).
                           A estratificação da etapa 0 garante ao menos 1 captura
                           por região presente no dataset (ex.: as 26 regiões do
                           datasets/e1), de modo que N menor que o número de
                           regiões resulta em 1 captura por região.
  -q, --shodan-queries N   Alimenta a etapa 6 apenas com as N primeiras linhas do CSV
                           enriquecido; cada IP de origem novo consome ~1 consulta
                           Shodan (~1 s). Padrão: processa todas as linhas.
      --with-neo4j         Gera também output_neo4j.cypher (etapa 4). Requer os
                           arquivos enriched_unique_source_IPs.csv e
                           enriched_unique_destination_IPs.csv na raiz do projeto.
      --with-mysql         Importa também no MySQL/MariaDB (etapa 5). Requer servidor
                           ativo e credenciais configuradas em src/5_import_mysql.py.
  -h, --help               Exibe esta ajuda.

Exemplos:
  other/full_etl.sh
  other/full_etl.sh -d datasets/e1 -n 48
  other/full_etl.sh -d datasets/e1 -n 12 -q 60
  other/full_etl.sh -d datasets/e3 --with-mysql
EOF
}

log() { echo "[full_etl] $*"; }
die() { echo "[full_etl] ERRO: $*" >&2; exit 1; }

RUN_DIR="(ainda não criado)"
trap 'log "Falha na linha $LINENO — execução interrompida (artefatos parciais preservados em $RUN_DIR)"' ERR

while [[ $# -gt 0 ]]; do
    case "$1" in
        -d|--dataset)        DATASET="$2"; shift 2 ;;
        -n|--num-pcaps)      NUM_PCAPS="$2"; shift 2 ;;
        -q|--shodan-queries) SHODAN_QUERIES="$2"; shift 2 ;;
        --with-neo4j)        WITH_NEO4J=1; shift ;;
        --with-mysql)        WITH_MYSQL=1; shift ;;
        -h|--help)           usage; exit 0 ;;
        *)                   die "Opção desconhecida: $1 (use --help)" ;;
    esac
done

is_positive_int() { [[ "$1" =~ ^[1-9][0-9]*$ ]]; }

[[ -d "$DATASET" ]] || die "Diretório do dataset não encontrado: $DATASET"
[[ -z "$NUM_PCAPS" ]] || is_positive_int "$NUM_PCAPS" || die "--num-pcaps deve ser um inteiro positivo: $NUM_PCAPS"
[[ -z "$SHODAN_QUERIES" ]] || is_positive_int "$SHODAN_QUERIES" || die "--shodan-queries deve ser um inteiro positivo: $SHODAN_QUERIES"
command -v tshark >/dev/null 2>&1 || die "tshark não encontrado no PATH"

PY="python3"
if [[ -x "venv/bin/python" ]]; then
    PY="venv/bin/python"
fi

"$PY" -c 'import geoip2.database, awsipranges, shodan, dotenv' >/dev/null 2>&1 \
    || die "Dependências Python ausentes em $PY (geoip2, awsipranges, shodan, dotenv)"

if [[ ! -s ".env" ]] || ! grep -qE '^SHODAN_API_KEY=..+' ".env"; then
    die "SHODAN_API_KEY não encontrada em .env (necessária para a etapa 6)"
fi

if [[ "$WITH_NEO4J" -eq 1 ]]; then
    [[ -f "enriched_unique_source_IPs.csv" && -f "enriched_unique_destination_IPs.csv" ]] \
        || die "--with-neo4j exige enriched_unique_source_IPs.csv e enriched_unique_destination_IPs.csv na raiz do projeto (gere-os com o bloco de IPs únicos ativo em src/2_enrich_csv.py)"
fi

if [[ "$WITH_MYSQL" -eq 1 ]]; then
    "$PY" -c 'import mysql.connector' >/dev/null 2>&1 \
        || die "--with-mysql exige mysql.connector disponível em $PY"
fi

ORIGEM="$(basename "$(cd "$DATASET" && pwd)")"
ORIGEM="$(printf '%s' "$ORIGEM" | tr -c 'A-Za-z0-9._-' '_')"

STAMP="$(date +%Y%m%d_%H%M%S)"
RUN_DIR="datasets/execucao_pipeline_${ORIGEM}_${STAMP}"
SUFIXO=1
while [[ -e "$RUN_DIR" ]]; do
    SUFIXO=$((SUFIXO + 1))
    RUN_DIR="datasets/execucao_pipeline_${ORIGEM}_${STAMP}_${SUFIXO}"
done

DATASET_ABS="$(cd "$DATASET" && pwd)"

link_pcaps() {
    local limite="$1"
    mkdir -p "$RUN_DIR"
    local pcap
    for pcap in "${PCAPS[@]:0:$limite}"; do
        ln -sfn "$pcap" "$RUN_DIR/$(basename "$pcap")"
    done
}

log "Dataset de origem: $DATASET_ABS"
log "Diretório da execução: $RUN_DIR"

mapfile -t PCAPS < <(find "$DATASET_ABS" -maxdepth 1 -type f -name '*.pcap.gz' | LC_ALL=C sort)

if [[ -n "$NUM_PCAPS" ]]; then
    if "$PY" src/0_select_representative_subset.py "$DATASET_ABS" --output "$RUN_DIR" --max-files "$NUM_PCAPS"; then
        log "Etapa 0 concluída (amostra estratificada com até $NUM_PCAPS capturas)"
    else
        log "AVISO: etapa 0 não encontrou capturas com nomenclatura elegível; vinculando as primeiras $NUM_PCAPS por ordem alfabética"
        link_pcaps "$NUM_PCAPS"
    fi
else
    log "Sem --num-pcaps: utilizando todas as ${#PCAPS[@]} capturas da raiz do dataset"
    link_pcaps "${#PCAPS[@]}"
fi

mapfile -t SELECIONADOS < <(find "$RUN_DIR" -maxdepth 1 -type l -name '*.pcap.gz' | LC_ALL=C sort)
[[ ${#SELECIONADOS[@]} -gt 0 ]] || die "Nenhuma captura .pcap.gz disponível para processar em $RUN_DIR"
log "Capturas na execução: ${#SELECIONADOS[@]}"

log "Etapa 1 — extração tshark"
bash src/1_generate_tshark_csv.sh "$RUN_DIR"

ENRICHED="$RUN_DIR/output.enriched.csv.gz"

log "Etapa 2 — enriquecimento GeoIP + AWS"
zcat "$RUN_DIR/output.csv.gz" | "$PY" src/2_enrich_csv.py | gzip > "$ENRICHED"

read -r LINHAS FALLBACK < <(zcat "$ENRICHED" | awk -F, '{n++; if ($13 == "ZZ") f++} END {print n+0, f+0}')
if (( LINHAS > 0 && FALLBACK == LINHAS )); then
    log "AVISO: 100% dos destinos ficaram no fallback GeoIP/AWS (${LINHAS} linhas com ZZ/Unknown na coluna M-R)."
    log "AVISO: causa típica — destinos privados nas capturas (ex.: datasets/e1); para geo/região de destino significativos, processe destinos públicos (ex.: datasets/e3). Ver contexto/implementacoes_e_testes.md, seção C."
fi

log "Etapa 3 — resumo LaTeX"
zcat "$ENRICHED" | "$PY" src/3_summarize_radiation.py > "$RUN_DIR/output.tex"

if [[ -n "$SHODAN_QUERIES" ]]; then
    log "Etapa 6 — enriquecimento Shodan (limitado às $SHODAN_QUERIES primeiras linhas)"
    zcat "$ENRICHED" | awk -v n="$SHODAN_QUERIES" 'NR<=n' | "$PY" src/6_shodan_enrich.py | gzip > "$RUN_DIR/output.shodan.gz"
else
    log "Etapa 6 — enriquecimento Shodan (todas as linhas; cada IP novo consome 1 consulta)"
    zcat "$ENRICHED" | "$PY" src/6_shodan_enrich.py | gzip > "$RUN_DIR/output.shodan.gz"
fi

if [[ "$WITH_NEO4J" -eq 1 ]]; then
    log "Etapa 4 — grafo Neo4j (Cypher)"
    zcat "$ENRICHED" | "$PY" src/4_generate_graph.py > "$RUN_DIR/output_neo4j.cypher"
fi

if [[ "$WITH_MYSQL" -eq 1 ]]; then
    log "Etapa 5 — importação MySQL/MariaDB"
    zcat "$ENRICHED" | "$PY" src/5_import_mysql.py
fi

log "Execução concluída: $RUN_DIR"
log "Artefatos gerados:"
for ARQUIVO in subset_manifest.csv subset_manifest.json output.csv.gz output.enriched.csv.gz output.tex output.shodan.gz output_neo4j.cypher; do
    if [[ -e "$RUN_DIR/$ARQUIVO" ]]; then
        log "  $RUN_DIR/$ARQUIVO"
    fi
done
