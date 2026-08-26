Estrutura dos arquivos através do retorno de `tree -L 2 --noreport`
(excluindo `datasets/`, `venv/` e artefatos de ferramentas — não escanear `datasets/`):

Diretório raiz: `ibr-etl`

```
.
├── AGENTS.md                  # fonte única de verdade das regras operacionais
├── .env                       # segredos (SHODAN_API_KEY) — nunca commitar/expor
├── .env_example               # modelo do .env, sem valores reais
├── .gitignore
├── .opencode/
│   └── rules.md               # apenas redireciona para o AGENTS.md
├── backups/                   # inútil — ignorar completamente
│   ├── 2b_enrich_shodan.py
│   ├── academic_plan.py
│   ├── academic_plan.sh
│   ├── GeoLite2-City.mmdb     # GeoIP gratuita (obsoleta; vive só aqui)
│   └── shodan_cache.db
├── bashrc
├── contexto/
│   ├── claude_memory.md       # lições de sessões anteriores (auxiliar)
│   ├── Cloud_Telescope.md     # TCC do prof. Bortoluzzi (referência conceitual)
│   ├── dataset_e3.md            # diferenças entre datasets e uso nos testes (vivo)
│   ├── estrutura.md           # este arquivo (vivo)
│   ├── implementacoes_e_testes.md  # registro histórico de implementações/testes
│   ├── instrucoes.md          # processo detalhado de trabalho para agentes de IA
│   ├── pipeline.md            # etapas atuais do pipeline (vivo)
│   └── TCC_2_ArthurPereira_PosBanca.md  # TCC do Arthur (referência conceitual)
├── datasets/
│   └── e3/
├── Docker/
│   ├── docker-compose.yml
│   └── Dockerfile
├── GeoIP2-City.mmdb           # base MaxMind GeoIP licenciada (usada pelo pipeline)
├── logs/
│   ├── anomalous_entries.csv
│   ├── cacheinfo.txt
│   ├── retorno.json
│   ├── shodan_cache.json      # cache Shodan por IP (criado na 1ª execução da etapa 6)
│   ├── shodan_enrich.log
│   ├── summarize_radiation_dict_dump.txt
│   └── trimmed_entries.csv
├── opencode.json              # carrega .opencode/rules.md como instruções
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
│   ├── 1_generate_tshark_csv.py
│   ├── 2_enrich_csv.py
│   ├── 3_summarize_radiation.py
│   ├── 4_generate_graph.py
│   ├── 5_import_mysql.py
│   └── 6_shodan_enrich.py
├── tests/
│   ├── exemplos_de_testes.md  # living spec dos comandos de teste (vivo)
│   ├── poc_shodan.py
│   └── testes_shodan.py
└── venv/
```

Observações:

- `datasets/e3`: dataset-alvo com ~21.300 capturas brutas `.pcap.gz` (≈42.600 arquivos
  contando `.pcap.txt`). **Não listar, ler ou escanear** seu conteúdo (ver `AGENTS.md`).
- `datasets/execucao_pipeline_<origem>_<data_hora>/`: diretórios criados a cada
  execução do facilitador `other/full_etl.sh` (links simbólicos das capturas +
  artefatos `output*`). Cada execução é isolada; nada de execuções anteriores é
  removido ou alterado.
- `GeoLite2-City.mmdb` (gratuita) existe apenas em `backups/`; o pipeline usa a
  licenciada `GeoIP2-City.mmdb` (`src/2_enrich_csv.py:7`).
- `logs/shodan_cache.json` é criado na primeira execução da etapa 6 (cache Shodan).
- `backups/` é obsoleto; mantido apenas por histórico.
- Hierarquia e papéis da documentação: seção "Hierarquia da documentação" no
  `AGENTS.md`.

Dentro do diretório `e3` existem arquivos como (nomenclatura bruta):

`af-south-1a-13.244.104.42-20231219-2011.pcap.gz`
`af-south-1a-13.244.104.42-20231219-2011.pcap.txt`
`af-south-1a-13.244.104.42-20231220-2011.pcap.gz`
...

Padrão completo em `AGENTS.md` (Nomenclatura das capturas).
