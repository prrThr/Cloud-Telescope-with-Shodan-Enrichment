#!/bin/bash

DATASET_DIR=${1:?"Uso: $0 <diretório do dataset>  (ex: datasets/e1)"}
OUTPUT="${DATASET_DIR}/output.csv.gz"

if [ -f "${OUTPUT}" ]; then
	mv "${OUTPUT}" "${OUTPUT}.old"
fi

echo "tshark start"

for f in "${DATASET_DIR}"/*.pcap.gz
do
	echo "extracting data from ${f}"
	# -O ip,tcp,udp,icmp # Barry's advice
	# --log-level "critical" # this works in Ubuntu but not in Rocky
	time tshark -r $f -M 100000 -t ad -T fields -e _ws.col.Time -e ip.src -e ip.dst -e tcp.dstport -e tcp.flags.str -e udp.dstport -e icmp.type -Eseparator=, --log-level "critical" | gzip -c >> "${OUTPUT}"
done

echo "tshark end"
