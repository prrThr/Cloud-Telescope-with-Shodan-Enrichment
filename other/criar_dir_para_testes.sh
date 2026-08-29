#!/bin/bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

REGION="e3_sa-east-1"
DIR_TESTS_DESTINO="datasets/e3_full_test"

echo "1. Criar diretório de teste e extrair 50k pacotes (~14h de captura, ~1s de tshark)"
mkdir -p "$DIR_TESTS_DESTINO"

set +e
zcat "datasets/e3_full/${REGION}.pcap.gz" \
    | tshark -r - -c 50000 -T fields -E separator=, \
        -e frame.time \
        -e ip.src \
        -e ip.dst \
        -e tcp.dstport \
        -e tcp.flags.str \
        -e udp.dstport \
        -e icmp.type \
    | gzip > "${DIR_TESTS_DESTINO}/output.csv.gz"
PIPE_STATUS=("${PIPESTATUS[@]}")
set -e

# O zcat pode terminar com SIGPIPE (141) quando o tshark
# para após atingir os 50.000 pacotes. Isso é esperado.
if [[ "${PIPE_STATUS[1]}" -ne 0 ]]; then
    echo "ERRO: tshark terminou com código ${PIPE_STATUS[1]}" >&2
    exit "${PIPE_STATUS[1]}"
fi

if [[ "${PIPE_STATUS[2]}" -ne 0 ]]; then
    echo "ERRO: gzip terminou com código ${PIPE_STATUS[2]}" >&2
    exit "${PIPE_STATUS[2]}"
fi

echo "Extração concluída: ${DIR_TESTS_DESTINO}/output.csv.gz"

sleep 3

echo "2. Enriquecimento (sem --region pois destination IPs são públicos)"
zcat "${DIR_TESTS_DESTINO}/output.csv.gz" \
    | python3 src/2_enrich_csv.py \
    | gzip > "${DIR_TESTS_DESTINO}/output.enriched.csv.gz"

sleep 3

echo "3. Validar"

echo "Colunas: $(zcat "${DIR_TESTS_DESTINO}/output.enriched.csv.gz" \
    | head -n 1 \
    | awk -F',' '{print NF}')"

echo "Regiões destino:"
zcat "${DIR_TESTS_DESTINO}/output.enriched.csv.gz" \
    | awk -F',' '{print $17}' \
    | sort \
    | uniq -c \
    | sort -rn \
    | head -n 10

# Explicação:
#   50.000 pacotes a ~1 pacote/s = ~14 horas de captura representativa
#   tshark -c 50000 extrai só o que precisa (~5-10s)
#   IPs de destino são públicos (tráfego real de internet background radiation, sem NAT)
#   GeoIP e awsipranges devem resolver normalmente (sem fallback ZZ)
#   Sem necessidade de --region

# Se quiser múltiplas regiões (mais representativo):
#for reg in sa-east-1 af-south-1 eu-west-1; do
#    zcat "datasets/e3_full/e3_${reg}.pcap.gz" \
#        | tshark -r - -c 20000 -T fields -E separator=, \
#            -e frame.time -e ip.src -e ip.dst \
#            -e tcp.dstport -e tcp.flags.str \
#            -e udp.dstport -e icmp.type
#done | gzip > "${DIR_TESTS_DESTINO}/output.csv.gz"
