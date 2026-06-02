#!/bin/bash
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATASET=${1:-"datasets/e1"}

step0="nohup"
step1="${PROJECT_ROOT}/src/1_generate_tshark_csv.sh ${DATASET} &&"
step2="zcat ${DATASET}/output.csv.gz | python ${PROJECT_ROOT}/src/2_enrich_csv.py | gzip > ${DATASET}/output.enriched.csv.gz &&"
step3="zcat ${DATASET}/output.enriched.csv.gz | python ${PROJECT_ROOT}/src/3_summarize_radiation.py > ${DATASET}/output.tex"

echo "$step0 $step1 $step2 $step3"
