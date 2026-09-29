#!/bin/bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

DATASET=""
NEW_QUERIES=""
PACKET_LIMIT=""
ROUNDS=""
WORK_DIR=""
STOP_FILE=""
CACHE_FILE=""
FORCE_FINAL=0
LOG=""

usage() {
cat <<EOF
Uso: other/shodan_rotation.sh -d DIR -q N [opções]

Coleta Shodan ROTATIVA entre os agregados de um diretório (ex.: datasets/e3_full).
Em vez de esgotar uma região por vez, o script processa até N consultas NOVAS por
região e "pula" para a próxima, acumulando cobertura de todos os agregados ao longo
do tempo. O cache global (logs/shodan_cache.json) é compartilhado: cache hits não
consomem crédito nem respeitam rate-limit, então cada rodada avança de fato.

Para cada agregado, o script prepara uma vez o CSV enriquecido
(regions/<região>/output.enriched.csv.gz) e depois roda a etapa 6
(6_shodan_enrich.py --max-new-queries N) sobre ele, descartando o stdout e
populando o cache. Regiões já esgotadas são marcadas (.done) e puladas nas rodadas
seguintes. Ao final, quando todas as regiões estiverem concluídas, o script gera
output.enriched.csv.gz e output.shodan.csv.gz (28 colunas) numa passada rápida
(tudo cache hit).

Opções:
  -d, --dataset DIR        Diretório com capturas .pcap.gz (obrigatório; ex.:
                           datasets/e3_full ou datasets/e3_raw).
  -q, --new-queries N      Consultas NOVAS por região por rodada (obrigatório).
  -p, --packet-limit N     Limite de pacotes por captura na extração (tshark -c),
                           opcional; acelera a preparação do enriquecido.
  -r, --rounds R           Número máximo de rodadas completas. Padrão: sem limite
                           (roda até todas as regiões concluírem ou até o
                           --stop-file).
  -o, --work-dir DIR       Diretório de trabalho (padrão:
                           datasets/rotacao_shodan_<origem>_<data_hora>). Aponte
                           para um diretório existente para RETOMAR uma coleta.
  -s, --stop-file ARQ      Marcador de parada (padrão: <work-dir>/stop_shodan).
                           Ao criar o arquivo com \`touch\`, a coleta encerra
                           graciosamente após a região corrente e o cache é
                           persistido.
  -c, --cache-file ARQ     Cache Shodan compartilhado (padrão do módulo:
                           logs/shodan_cache.json).
      --final              Gera a saída final mesmo se houver regiões pendentes
                           (pode consumir consultas novas; use com cautela).
  -h, --help               Exibe esta ajuda.

Exemplos:
  other/shodan_rotation.sh -d datasets/e3_full -q 1000
  other/shodan_rotation.sh -d datasets/e3_full -q 1000 -o datasets/rotacao_shodan_e3_full_20260919_120000
  other/shodan_rotation.sh -d datasets/e3_raw -q 500 -p 50000 -r 1
EOF
}

log() {
    if [[ -n "$LOG" ]]; then
        echo "[rotacao] $*" | tee -a "$LOG"
    else
        echo "[rotacao] $*"
    fi
}
die() { echo "[rotacao] ERRO: $*" >&2; exit 1; }

WORK_DIR_TXT="(ainda não criado)"
trap 'log "Falha na linha $LINENO — execução encerrada com erro (diretório: $WORK_DIR_TXT)"' ERR

while [[ $# -gt 0 ]]; do
    case "$1" in
        -d|--dataset)       DATASET="$2"; shift 2 ;;
        -q|--new-queries)   NEW_QUERIES="$2"; shift 2 ;;
        -p|--packet-limit)  PACKET_LIMIT="$2"; shift 2 ;;
        -r|--rounds)        ROUNDS="$2"; shift 2 ;;
        -o|--work-dir)      WORK_DIR="$2"; shift 2 ;;
        -s|--stop-file)     STOP_FILE="$2"; shift 2 ;;
        -c|--cache-file)    CACHE_FILE="$2"; shift 2 ;;
        --final)            FORCE_FINAL=1; shift ;;
        -h|--help)          usage; exit 0 ;;
        *)                  die "Opção desconhecida: $1 (use --help)" ;;
    esac
done

is_positive_int() { [[ "$1" =~ ^[1-9][0-9]*$ ]]; }

[[ -d "$DATASET" ]] || die "Diretório do dataset não encontrado: $DATASET"
[[ -n "$NEW_QUERIES" ]] || die "-q/--new-queries é obrigatório"
is_positive_int "$NEW_QUERIES" || die "--new-queries deve ser um inteiro positivo: $NEW_QUERIES"
[[ -z "$PACKET_LIMIT" ]] || is_positive_int "$PACKET_LIMIT" || die "--packet-limit deve ser um inteiro positivo: $PACKET_LIMIT"
[[ -z "$ROUNDS" ]] || is_positive_int "$ROUNDS" || die "--rounds deve ser um inteiro positivo: $ROUNDS"

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

DATASET_ABS="$(cd "$DATASET" && pwd)"
mapfile -t PCAPS < <(find "$DATASET_ABS" -maxdepth 1 -type f -name '*.pcap.gz' | LC_ALL=C sort)
[[ ${#PCAPS[@]} -gt 0 ]] || die "Nenhuma captura .pcap.gz em $DATASET"

ORIGEM="$(basename "$DATASET_ABS")"
ORIGEM="$(printf '%s' "$ORIGEM" | tr -c 'A-Za-z0-9._-' '_')"

if [[ -z "$WORK_DIR" ]]; then
    WORK_DIR="datasets/rotacao_shodan_${ORIGEM}_$(date +%Y%m%d_%H%M%S)"
fi
mkdir -p "$WORK_DIR/regions"
WORK_DIR_TXT="$WORK_DIR"
LOG="$WORK_DIR/rotacao.log"
[[ -z "$STOP_FILE" ]] && STOP_FILE="$WORK_DIR/stop_shodan"
rm -f -- "$STOP_FILE"

regiao_de() { basename "$1" .pcap.gz; }
rdir_de()   { echo "$WORK_DIR/regions/$(regiao_de "$1")"; }

preparar_regiao() {
    local pcap="$1" region rdir
    region="$(regiao_de "$pcap")"
    rdir="$(rdir_de "$pcap")"
    mkdir -p "$rdir"
    if [[ -s "$rdir/output.enriched.csv.gz" ]]; then
        return 0
    fi
    ln -sfn "$pcap" "$rdir/$(basename "$pcap")"
    log "[$region] extração tshark..."
    local cmd=("$PY" src/1_generate_tshark_csv.py "$rdir")
    if [[ -n "$PACKET_LIMIT" ]]; then
        cmd+=(--packet-limit "$PACKET_LIMIT")
    fi
    "${cmd[@]}" >/dev/null
    log "[$region] enriquecimento GeoIP + AWS..."
    zcat "$rdir/output.csv.gz" | "$PY" src/2_enrich_csv.py | gzip > "$rdir/output.enriched.csv.gz"
}

rodar_regiao() {
    local pcap="$1" rdir st=0
    rdir="$(rdir_de "$pcap")"
    local opts=(--max-new-queries "$NEW_QUERIES" --stop-file "$STOP_FILE")
    if [[ -n "$CACHE_FILE" ]]; then
        opts+=(--cache-file "$CACHE_FILE")
    fi
    "$PY" src/6_shodan_enrich.py \
        "${opts[@]}" \
        < <(zcat "$rdir/output.enriched.csv.gz") \
        > /dev/null 2> >(tee -a "$rdir/shodan.log" >&2) || st=$?
    return "$st"
}

todas_concluidas() {
    local pcap
    for pcap in "${PCAPS[@]}"; do
        [[ -e "$(rdir_de "$pcap")/.done" ]] || return 1
    done
    return 0
}

gerar_saida_final() {
    log "Consolidando output.enriched.csv.gz (todas as regiões)..."
    {
        local pcap
        for pcap in "${PCAPS[@]}"; do
            zcat "$(rdir_de "$pcap")/output.enriched.csv.gz"
        done
    } | gzip > "$WORK_DIR/output.enriched.csv.gz"

    log "Gerando output.shodan.csv.gz (cache hits — rápido)..."
    local opts=()
    if [[ -n "$CACHE_FILE" ]]; then
        opts+=(--cache-file "$CACHE_FILE")
    fi
    {
        local pcap
        for pcap in "${PCAPS[@]}"; do
            zcat "$(rdir_de "$pcap")/output.enriched.csv.gz"
        done
    } | "$PY" src/6_shodan_enrich.py "${opts[@]}" | gzip > "$WORK_DIR/output.shodan.csv.gz"
}

log "Dataset: $DATASET_ABS"
log "Diretório de trabalho: $WORK_DIR"
log "Regiões: ${#PCAPS[@]} | consultas novas por região/rodada: $NEW_QUERIES"
log "Marcador de parada: $STOP_FILE"

rodada=0
parar=0
while :; do
    rodada=$((rodada + 1))
    log "===== Rodada $rodada ====="
    for pcap in "${PCAPS[@]}"; do
        region="$(regiao_de "$pcap")"
        if [[ -e "$(rdir_de "$pcap")/.done" ]]; then
            continue
        fi
        preparar_regiao "$pcap"
        log "[$region] coletando até $NEW_QUERIES consultas novas..."
        st=0
        rodar_regiao "$pcap" || st=$?
        if [[ -e "$STOP_FILE" ]]; then
            log "Marcador de parada detectado — encerrando a rotação."
            parar=1
            break
        fi
        if (( st == 0 )); then
            touch "$(rdir_de "$pcap")/.done"
            log "[$region] concluída (sem IPs novos pendentes)."
        elif (( st == 10 )); then
            log "[$region] limite de $NEW_QUERIES consultas novas atingido — próxima região."
        else
            die "falha na etapa 6 da região $region (código $st)"
        fi
    done

    if (( parar == 1 )); then
        break
    fi
    if todas_concluidas; then
        log "Todas as regiões concluídas."
        break
    fi
    if [[ -n "$ROUNDS" ]] && (( rodada >= ROUNDS )); then
        log "Número de rodadas configurado ($ROUNDS) atingido."
        break
    fi
done

if todas_concluidas; then
    gerar_saida_final
elif (( FORCE_FINAL == 1 )); then
    log "AVISO: --final forçado com regiões pendentes — pode consumir consultas novas."
    gerar_saida_final
else
    log "Rotação interrompida com regiões pendentes; saída final não gerada."
    log "Para retomar/gerar depois: other/shodan_rotation.sh -d $DATASET -q $NEW_QUERIES -o $WORK_DIR"
fi

log "Diretório da coleta: $WORK_DIR"
log "Concluído."
