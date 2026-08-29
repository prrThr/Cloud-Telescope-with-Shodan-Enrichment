#!/bin/bash

DATASET_DIR=${1:?"Uso: $0 <diretório do dataset>  (ex: datasets/e1)"}
OUTPUT="${DATASET_DIR}/output.csv.gz"

if [ -f "${OUTPUT}" ]; then
	mv "${OUTPUT}" "${OUTPUT}.old"
fi

echo "tshark start"

declare -a LAST_FILES=()
PREV_COUNT=0

for f in "${DATASET_DIR}"/*.pcap.gz
do
	LAST_FILES+=("${f##*/}")
	if [ ${#LAST_FILES[@]} -gt 5 ]; then
		LAST_FILES=("${LAST_FILES[@]:1}")
	fi

	if [ "$PREV_COUNT" -gt 0 ]; then
		printf "\033[%dA" "$PREV_COUNT"
	fi

	for (( i=0; i<${#LAST_FILES[@]}; i++ )); do
		printf "\r\033[K  - %s\n" "${LAST_FILES[$i]}"
	done

	PREV_COUNT=${#LAST_FILES[@]}

	# -O ip,tcp,udp,icmp # Barry's advice
	# --log-level "critical" # this works in Ubuntu but not in Rocky
	time zcat "$f" | tshark -r - -M 100000 -t ad -T fields -e _ws.col.Time -e ip.src -e ip.dst -e tcp.dstport -e tcp.flags.str -e udp.dstport -e icmp.type -Eseparator=, --log-level "critical" | gzip -c >> "${OUTPUT}"
done

echo "tshark end"
