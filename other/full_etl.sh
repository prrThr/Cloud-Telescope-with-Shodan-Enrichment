#!/bin/bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

DATASET=""
NUM_PCAPS=""
PACKET_LIMIT=""
SHODAN_QUERIES=""
STOP_FILE=""
CACHE_FILE=""
RATE_LIMIT=""
CACHE_SAVE_EVERY=""
REGION=""
WITH_NEO4J=0
WITH_MYSQL=0
HAS_ANALYSIS=0

usage() {
cat <<EOF
Uso: other/full_etl.sh [opções]

Executa o pipeline principal por inteiro (etapas 0→7), criando um novo diretório
de execução em datasets/execucao_pipeline_<origem>_<data_hora>. O dataset de origem
é apenas lido (via links simbólicos) e execuções anteriores nunca são removidas ou
alteradas.

Artefatos sempre gerados no diretório da execução:
  output.csv.gz            etapa 1 — extração tshark
  output.enriched.csv.gz   etapa 2 — enriquecimento GeoIP + AWS
  output.tex               etapa 3 — resumo LaTeX
  output.shodan.csv.gz     etapa 6 — enriquecimento Shodan
  *.csv / *.png            etapa 7 — análise de resultados (os_distribution,
                           org_ranking, isp_ranking, top_ports, port_cves,
                           ganho_shodan, comparacao_pipeline [só CSV],
                           geo_os_cross)

Opções:
  -d, --dataset DIR        Diretório de origem das capturas (obrigatório, sem padrão;
                           ex.: datasets/e3_raw ou datasets/e3_full).
                           Com nomenclatura bruta (<região><az>-<IP>-<data>-<hora>),
                           a seleção usa a etapa 0 (estratificada por região); sem
                           nomenclatura elegível (ex.: agregados do datasets/e3_full),
                           as capturas são vinculadas por ordem alfabética do nome.
  -n, --num-pcaps N        Quantidade de capturas .pcap a utilizar
                           (padrão: todas as capturas da raiz do dataset).
                           A estratificação da etapa 0 garante ao menos 1 captura
                           por região presente no dataset (ex.: as 26 regiões do
                           datasets/e3_raw), de modo que N menor que o número de
                           regiões resulta em 1 captura por região.
  -q, --shodan-queries N   Limita a etapa 6 a até N consultas NOVAS à API Shodan
                           (cache hits não contam). A etapa 6 encerra graciosamente
                           ao atingir N consultas novas e a execução segue para a
                           etapa 7. Padrão: processa todas as linhas.
  -s, --stop-file ARQ      Marcador de parada da etapa 6. Quando o arquivo ARQ existir,
                           a coleta Shodan encerra graciosamente (flush do cache e
                           output.shodan.csv.gz íntegro) e a execução segue. Padrão:
                           <diretório da execução>/stop_shodan. Para interromper uma
                           coleta longa (ex.: madrugada), crie o arquivo com \`touch\`.
  -c, --cache-file ARQ     Cache Shodan a usar na etapa 6 (e na análise da etapa 7).
                           Padrão: logs/shodan_cache.json (default do módulo).
      --rate-limit N       Delay entre requisições à API Shodan, em segundos
                           (repassado à etapa 6; padrão do módulo: 1.0).
      --cache-save-every N Grava o cache Shodan em disco a cada N IPs novos
                           (repassado à etapa 6; padrão do módulo: 500).
      --region REGIAO      Região AWS de destino usada como fallback na etapa 2 quando
                           100% dos destinos não resolvem via GeoIP/awsipranges.
  -p, --packet-limit N     Limite de pacotes por captura na etapa 1 (repassado ao
                           tshark via -c). Reduz drasticamente o tempo de extração
                           (ex.: -p 50000 ≈ 5-10 s por arquivo). Padrão: sem limite.
      --with-neo4j         Gera também output_neo4j.cypher (etapa 4). Requer os
                           arquivos enriched_unique_source_IPs.csv e
                           enriched_unique_destination_IPs.csv na raiz do projeto.
      --with-mysql         Importa também no MySQL/MariaDB (etapa 5). Requer servidor
                           ativo e credenciais configuradas em src/5_import_mysql.py.
  -h, --help               Exibe esta ajuda.

Interrupção: Ctrl+C durante uma etapa finaliza-a graciosamente, preserva os
artefatos parciais e segue para a próxima etapa (etapas dependentes de entrada
ausente são puladas). Um segundo Ctrl+C encerra imediatamente. Para a etapa 6
(Shodan), o método recomendado de interrupção é o marcador --stop-file (evita
perda de pendências de cache e .gz truncado).

Exemplos:
  other/full_etl.sh -d datasets/e3_full
  other/full_etl.sh -d datasets/e3_raw -n 48
  other/full_etl.sh -d datasets/e3_raw -n 12 -q 60
  other/full_etl.sh -d datasets/e3_full --with-mysql
  other/full_etl.sh --dataset datasets/e3_raw --num-pcaps 10 --shodan-queries 60
  other/full_etl.sh -d datasets/e3_full -n 1 -p 60 -q 60
EOF
}

log() { echo "[full_etl] $*"; }
die() { echo "[full_etl] ERRO: $*" >&2; exit 1; }

RUN_DIR="(ainda não criado)"
trap 'log "Falha na linha $LINENO — execução encerrada com erro (artefatos parciais preservados em $RUN_DIR)"' ERR

INT_COUNT=0
INT_VISTO=0
STAGE_PID=""

matar_arvore() {
    local pid="$1" filho
    for filho in $(pgrep -P "$pid" 2>/dev/null); do
        matar_arvore "$filho"
    done
    kill -TERM "$pid" 2>/dev/null || true
}

ao_interromper() {
    INT_COUNT=$((INT_COUNT + 1))
    if (( INT_COUNT >= 2 )); then
        log "Segundo Ctrl+C recebido — encerrando agora (artefatos parciais preservados em $RUN_DIR)."
        exit 130
    fi
    INT_VISTO=1
    log "Ctrl+C recebido — interrompendo a etapa atual graciosamente (pressione novamente para sair imediatamente)."
    if [[ -n "$STAGE_PID" ]] && kill -0 "$STAGE_PID" 2>/dev/null; then
        matar_arvore "$STAGE_PID"
    fi
}
trap ao_interromper INT TERM

while [[ $# -gt 0 ]]; do
    case "$1" in
        -d|--dataset)        DATASET="$2"; shift 2 ;;
        -n|--num-pcaps)      NUM_PCAPS="$2"; shift 2 ;;
        -p|--packet-limit)   PACKET_LIMIT="$2"; shift 2 ;;
        -q|--shodan-queries) SHODAN_QUERIES="$2"; shift 2 ;;
        -s|--stop-file)      STOP_FILE="$2"; shift 2 ;;
        -c|--cache-file)     CACHE_FILE="$2"; shift 2 ;;
        --rate-limit)        RATE_LIMIT="$2"; shift 2 ;;
        --cache-save-every)  CACHE_SAVE_EVERY="$2"; shift 2 ;;
        --region)            REGION="$2"; shift 2 ;;
        --with-neo4j)        WITH_NEO4J=1; shift ;;
        --with-mysql)        WITH_MYSQL=1; shift ;;
        -h|--help)           usage; exit 0 ;;
        *)                   die "Opção desconhecida: $1 (use --help)" ;;
    esac
done

is_positive_int() { [[ "$1" =~ ^[1-9][0-9]*$ ]]; }

[[ -d "$DATASET" ]] || die "Diretório do dataset não encontrado: $DATASET"
[[ -z "$NUM_PCAPS" ]] || is_positive_int "$NUM_PCAPS" || die "--num-pcaps deve ser um inteiro positivo: $NUM_PCAPS"
[[ -z "$PACKET_LIMIT" ]] || is_positive_int "$PACKET_LIMIT" || die "--packet-limit deve ser um inteiro positivo: $PACKET_LIMIT"
[[ -z "$SHODAN_QUERIES" ]] || is_positive_int "$SHODAN_QUERIES" || die "--shodan-queries deve ser um inteiro positivo: $SHODAN_QUERIES"
[[ -z "$CACHE_SAVE_EVERY" ]] || is_positive_int "$CACHE_SAVE_EVERY" || die "--cache-save-every deve ser um inteiro positivo: $CACHE_SAVE_EVERY"
[[ -z "$RATE_LIMIT" ]] || [[ "$RATE_LIMIT" =~ ^[0-9]+([.][0-9]+)?$ ]] || die "--rate-limit deve ser um número positivo: $RATE_LIMIT"
command -v tshark >/dev/null 2>&1 || die "tshark não encontrado no PATH"

PY="python3"
if [[ -x "venv/bin/python" ]]; then
    PY="venv/bin/python"
fi

"$PY" -c 'import geoip2.database, awsipranges, shodan, dotenv' >/dev/null 2>&1 \
    || die "Dependências Python ausentes em $PY (geoip2, awsipranges, shodan, dotenv)"

if "$PY" -c 'import pandas, matplotlib' >/dev/null 2>&1; then
    HAS_ANALYSIS=1
else
    log "AVISO: pandas/matplotlib ausentes em $PY — a etapa 7 (análise de resultados) será pulada."
fi

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

if [[ -z "$STOP_FILE" ]]; then
    STOP_FILE="$RUN_DIR/stop_shodan"
fi

DATASET_ABS="$(cd "$DATASET" && pwd)"

link_pcaps() {
    local limite="$1"
    mkdir -p "$RUN_DIR"
    local pcap
    for pcap in "${PCAPS[@]:0:$limite}"; do
        ln -sfn "$pcap" "$RUN_DIR/$(basename "$pcap")"
    done
}

exige() {
    if [[ ! -s "$1" ]]; then
        log "AVISO: entrada $1 indisponível ou vazia — pulando esta etapa."
        return 1
    fi
}

rodar() {
    local rotulo="$1" funcao="$2"
    INT_COUNT=0
    INT_VISTO=0
    STAGE_PID=""
    log "Etapa $rotulo"
    local st=0
    ( "$funcao" ) & STAGE_PID=$!
    until ! kill -0 "$STAGE_PID" 2>/dev/null; do
        wait "$STAGE_PID" 2>/dev/null
        sleep 0.05
    done
    wait "$STAGE_PID" 2>/dev/null || st=$?
    STAGE_PID=""
    if (( INT_VISTO == 1 )); then
        log "AVISO: etapa $rotulo interrompida pelo usuário (Ctrl+C) — mantendo os dados parciais e seguindo para a próxima etapa."
    elif (( st != 0 )); then
        die "falha na etapa $rotulo (código $st)"
    fi
}

etapa1_extracao() {
    local cmd=("$PY" src/1_generate_tshark_csv.py "$RUN_DIR")
    if [[ -n "$PACKET_LIMIT" ]]; then
        cmd+=(--packet-limit "$PACKET_LIMIT")
    fi
    "${cmd[@]}"
}

etapa2_enriquecimento() {
    exige "$RUN_DIR/output.csv.gz" || return 0
    local st=0
    local enrich_args=()
    [[ -z "$REGION" ]] || enrich_args+=(--region "$REGION")
    zcat "$RUN_DIR/output.csv.gz" | "$PY" src/2_enrich_csv.py "${enrich_args[@]}" | gzip > "$ENRICHED" || st=$?
    if (( st == 130 || st == 143 )); then
        return "$st"
    fi
    if (( st != 0 )) && [[ ! -s "$ENRICHED" ]]; then
        return "$st"
    fi
    if (( st != 0 )); then
        log "AVISO: entrada possivelmente truncada por interrupção anterior — processando apenas os dados recuperáveis."
    fi
    read -r LINHAS FALLBACK < <(zcat "$ENRICHED" | awk -F, '{n++; if ($13 == "ZZ") f++} END {print n+0, f+0}') || true
    LINHAS=${LINHAS:-0}
    FALLBACK=${FALLBACK:-0}
    if (( LINHAS > 0 && FALLBACK == LINHAS )); then
        log "AVISO: 100% dos destinos ficaram no fallback GeoIP/AWS (${LINHAS} linhas com ZZ/Unknown na coluna M-R)."
        log "AVISO: causa típica — destinos privados nas capturas (ex.: datasets/e3_raw); para geo/região de destino significativos, processe destinos públicos (ex.: datasets/e3_full). Ver contexto/implementacoes_e_testes.md, seção C."
    fi
}

etapa3_resumo() {
    exige "$ENRICHED" || return 0
    local st=0
    zcat "$ENRICHED" | "$PY" src/3_summarize_radiation.py > "$RUN_DIR/output.tex" || st=$?
    if (( st == 130 || st == 143 )); then
        return "$st"
    fi
    if (( st != 0 )) && [[ ! -s "$RUN_DIR/output.tex" ]]; then
        return "$st"
    fi
    (( st == 0 )) || log "AVISO: entrada possivelmente truncada por interrupção — resumo gerado sobre os dados recuperáveis."
    return 0
}

etapa6_shodan() {
    exige "$ENRICHED" || return 0
    local st=0
    local shodan_args=(--stop-file "$STOP_FILE")
    [[ -z "$CACHE_FILE" ]] || shodan_args+=(--cache-file "$CACHE_FILE")
    [[ -z "$RATE_LIMIT" ]] || shodan_args+=(--rate-limit "$RATE_LIMIT")
    [[ -z "$CACHE_SAVE_EVERY" ]] || shodan_args+=(--cache-save-every "$CACHE_SAVE_EVERY")
    [[ -z "$SHODAN_QUERIES" ]] || shodan_args+=(--max-new-queries "$SHODAN_QUERIES")
    rm -f -- "$STOP_FILE"
    zcat "$ENRICHED" | "$PY" src/6_shodan_enrich.py "${shodan_args[@]}" | gzip > "$RUN_DIR/output.shodan.csv.gz" || st=$?
    if (( st == 130 || st == 143 )); then
        return "$st"
    fi
    if (( st == 10 )); then
        log "Etapa 6 encerrada por limite de consultas novas (--shodan-queries $SHODAN_QUERIES)."
        return 0
    fi
    if (( st != 0 )) && [[ ! -s "$RUN_DIR/output.shodan.csv.gz" ]]; then
        return "$st"
    fi
    (( st == 0 )) || log "AVISO: entrada possivelmente truncada por interrupção — Shodan aplicado aos dados recuperáveis."
    return 0
}

etapa7_analise() {
    (( HAS_ANALYSIS )) || return 0
    exige "$RUN_DIR/output.shodan.csv.gz" || return 0
    local st=0
    local analise_args=(--original-csv "$ENRICHED" --output-dir "$RUN_DIR")
    [[ -z "$CACHE_FILE" ]] || analise_args+=(--cache-file "$CACHE_FILE")
    zcat "$RUN_DIR/output.shodan.csv.gz" | "$PY" src/7_analyze_results.py "${analise_args[@]}" || st=$?
    if (( st == 130 || st == 143 )); then
        return "$st"
    fi
    (( st == 0 )) || log "AVISO: análise de resultados (etapa 7) encerrou com código $st."
    return 0
}

etapa4_neo4j() {
    (( WITH_NEO4J )) || return 0
    exige "$ENRICHED" || return 0
    local st=0
    zcat "$ENRICHED" | "$PY" src/4_generate_graph.py > "$RUN_DIR/output_neo4j.cypher" || st=$?
    if (( st == 130 || st == 143 )); then
        return "$st"
    fi
    if (( st != 0 )) && [[ ! -s "$RUN_DIR/output_neo4j.cypher" ]]; then
        return "$st"
    fi
    (( st == 0 )) || log "AVISO: entrada possivelmente truncada por interrupção — Cypher gerado sobre os dados recuperáveis."
    return 0
}

etapa5_mysql() {
    (( WITH_MYSQL )) || return 0
    exige "$ENRICHED" || return 0
    local st=0
    zcat "$ENRICHED" | "$PY" src/5_import_mysql.py || st=$?
    if (( st == 130 || st == 143 )); then
        return "$st"
    fi
    if (( st != 0 )); then
        log "AVISO: importação MySQL/MariaDB encerrou com código $st (dados parciais podem ter sido inseridos)."
    fi
    return 0
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

ENRICHED="$RUN_DIR/output.enriched.csv.gz"

rodar "1 — extração tshark" etapa1_extracao
rodar "2 — enriquecimento GeoIP + AWS" etapa2_enriquecimento
if [[ -n "$SHODAN_QUERIES" ]]; then
    log "Etapa 6 limitada a até $SHODAN_QUERIES consultas novas à API Shodan (cache hits não contam)"
else
    log "Etapa 6 processará todas as linhas; cada IP novo consome 1 consulta"
fi
log "Marcador de parada da etapa 6 (Shodan): $STOP_FILE"
log "Para encerrar a coleta e finalizar a execução graciosamente: touch \"$STOP_FILE\""
rodar "3 — resumo LaTeX" etapa3_resumo
rodar "6 — enriquecimento Shodan" etapa6_shodan
rodar "7 — análise de resultados" etapa7_analise
rodar "4 — grafo Neo4j (Cypher)" etapa4_neo4j
rodar "5 — importação MySQL/MariaDB" etapa5_mysql

log "Execução concluída: $RUN_DIR"
log "Artefatos gerados:"
for ARQUIVO in subset_manifest.csv subset_manifest.json output.csv.gz output.enriched.csv.gz output.tex output.shodan.csv.gz output_neo4j.cypher os_distribution.csv org_ranking.csv isp_ranking.csv top_ports.csv port_cves.csv ganho_shodan.csv comparacao_pipeline.csv geo_os_cross.csv; do
    if [[ -e "$RUN_DIR/$ARQUIVO" ]]; then
        log "  $RUN_DIR/$ARQUIVO"
    fi
done
