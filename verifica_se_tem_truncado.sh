#!/bin/bash

WORK=datasets/rotacao_shodan_e3_full_20260919_103421

echo -e '=========== Verifica se tem truncado\n'

for f in "$WORK"/regions/*/output.enriched.csv.gz; do
    if zcat "$f" >/dev/null 2>&1; then echo "OK   $f"; else echo "RUIM $f"; fi
done

echo -e '=========== Consolidar o enriquecido das regiões preparadas\n'

{ for f in "$WORK"/regions/*/output.enriched.csv.gz; do zcat "$f"; done; } \
    | gzip > "$WORK/output.enriched.csv.gz"

echo -e '=========== Gerar o CSV de 28 colunas somente com o cache (sem API, não altera o cache)\n'

zcat "$WORK/output.enriched.csv.gz" | venv/bin/python -c '
import sys, importlib.util
spec = importlib.util.spec_from_file_location("m6", "src/6_shodan_enrich.py")
m6 = importlib.util.module_from_spec(spec); spec.loader.exec_module(m6)
cache = m6.ShodanCache("logs/shodan_cache.json", save_every=10**9)
cache.set = lambda ip, rec: None
cache.flush = lambda: None
m6.query_shodan = lambda api, ip, retries=m6.MAX_RETRIES: m6._empty_record(ip, reason="cache_only")
m6.process_pipeline(None, cache, rate_limit=0)
' | gzip > "$WORK/output.shodan.csv.gz"

echo -e '=========== Conferir\n'

zcat "$WORK/output.shodan.csv.gz" | head -1 | awk -F, '{print NF}'
zcat "$WORK/output.shodan.csv.gz" | wc -l

echo -e '=========== Análise e visualizações\n'
zcat "$WORK/output.shodan.csv.gz" | venv/bin/python src/7_analyze_results.py \
    --original-csv "$WORK/output.enriched.csv.gz" --output-dir "$WORK"

