Estrutura dos arquivos através do retorno de `tree -L 2`:

Diretório raiz: `ibr-etl`

```
.
├── backups
│   ├── 2b_enrich_shodan.py
│   └── shodan_cache.db
├── bashrc
├── datasets
│   ├── e1
│   └── e3
├── Docker
│   ├── docker-compose.yml
│   └── Dockerfile
├── GeoLite2-City.mmdb
├── logs
│   ├── retorno.json
│   └── shodan_enrich.log
├── other
│   ├── aggregate_pcaps.sh
│   ├── capinfos_packet_count.sh
│   ├── daily_distribution.py
│   ├── full_etl.sh
│   ├── generate_capinfos.sh
│   ├── import_pcaps_onto_securityonion.sh
│   ├── process_regions.sh
│   └── testawsranges.py
├── README.md
├── src
│   ├── 1_generate_tshark_csv.sh
│   ├── 2_enrich_csv.py
│   ├── 3_summarize_radiation.py
│   ├── 4_generate_graph.py
│   ├── 5_import_mysql.py
│   └── 6_shodan_enrich.py
├── tests
│   ├── poc_shodan.py
│   └── testes_shodan.py
└── venv
    ├── bin
    ├── include
    ├── lib
    ├── lib64 -> lib
    └── pyvenv.cfg

15 directories, 26 files
```

Os diretórios `e1` e `e3` possuem os datasets (dados coletados pelo Cloud Telescope).

Dentro do diretório `e1` existem os seguinte arquivos e diretórios:
`af-south-1b-13.244.71.194-20230502-0017.pcap.gz`
`af-south-1b-13.244.71.194-20230501-1217.pcap.txt`
`af-south-1b-13.244.71.194-20230501-1217.pcap.gz`
`af-south-1b-13.244.71.194-20230501-0017.pcap.txt`
...
`us-west-2a-54.245.220.116-20230501-0008.pcap.txt`
`us-west-2a-54.245.220.116-20230501-0008.pcap.gz`
`us-west-2a-54.214.221.78-20230430-0137.pcap.gz`
`us-west-2a-52.24.122.124-20230506-1218.pcap.txt`