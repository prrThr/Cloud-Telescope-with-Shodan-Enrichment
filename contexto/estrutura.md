Estrutura dos arquivos através do retorno de `tree -L 2 --noreport`:

Diretório raiz: `ibr-etl`

```
.
├── AGENTS.md
├── backups/                # inútil — ignorar completamente
│   ├── 2b_enrich_shodan.py
│   ├── academic_plan.py
│   ├── academic_plan.sh
│   ├── GeoLite2-City.mmdb
│   └── shodan_cache.db
├── bashrc
├── contexto/
│   ├── claude_memory.md
│   ├── Cloud_Telescope.md
│   ├── estrutura.md
│   ├── implementacoes_e_testes.md
│   ├── instrucoes.md
│   ├── pipeline.md
│   └── TCC_2_ArthurPereira_PosBanca.md
├── datasets/
│   ├── e1/
│   ├── e1_subset/
│   └── e3/
├── Docker/
│   ├── docker-compose.yml
│   └── Dockerfile
├── GeoIP2-City.mmdb
├── logs/
│   ├── anomalous_entries.csv
│   ├── cacheinfo.txt
│   ├── retorno.json
│   ├── shodan_enrich.log
│   └── trimmed_entries.csv
├── opencode.json
├── other/
│   ├── aggregate_pcaps.sh
│   ├── capinfos_packet_count.sh
│   ├── daily_distribution.py
│   ├── full_etl.sh
│   ├── generate_capinfos.sh
│   ├── import_pcaps_onto_securityonion.sh
│   ├── process_regions.sh
│   └── testawsranges.py
├── README.md
├── src/
│   ├── 0_select_representative_subset.py
│   ├── 1_generate_tshark_csv.sh
│   ├── 2_enrich_csv.py
│   ├── 3_summarize_radiation.py
│   ├── 4_generate_graph.py
│   ├── 5_import_mysql.py
│   ├── 6_shodan_enrich.py
│   └── __pycache__/
├── tests/
│   ├── exemplos_de_testes.md
│   ├── poc_shodan.py
│   └── testes_shodan.py
└── venv/
    ├── bin/
    ├── include/
    ├── lib/
    ├── lib64 -> lib/
    └── pyvenv.cfg
```

Observações:

- `datasets/e1`, `datasets/e1_subset` e `datasets/e3`: os dados brutos e o subconjunto
  de trabalho. Não listar, ler ou escanear seu conteúdo (ver `AGENTS.md`).
- `GeoLite2-City.mmdb` (gratuita) pode coexistir com `GeoIP2-City.mmdb` (licenciada);
  o pipeline usa a licenciada (`src/2_enrich_csv.py:7`).
- `logs/shodan_cache.json` é criado na primeira execução da etapa 6 (cache Shodan).
- `backups/` é obsoleto; mantido apenas por histórico.

Dentro do diretório `e1` existem os seguintes arquivos e diretórios:
`af-south-1b-13.244.71.194-20230502-0017.pcap.gz`
`af-south-1b-13.244.71.194-20230501-1217.pcap.txt`
`af-south-1b-13.244.71.194-20230501-1217.pcap.gz`
`af-south-1b-13.244.71.194-20230501-0017.pcap.txt`
...
`us-west-2a-54.245.220.116-20230501-0008.pcap.txt`
`us-west-2a-54.245.220.116-20230501-0008.pcap.gz`
`us-west-2a-54.214.221.78-20230430-0137.pcap.gz`
`us-west-2a-52.24.122.124-20230506-1218.pcap.txt`
