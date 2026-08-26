## Como funciona o Pipeline

- O pipeline é um fluxo ETL (Extract, Transform, Load) que processa capturas de tráfego de rede (IBR) coletadas pelo Cloud Telescope.
- O objetivo é transformar arquivos PCAP brutos em dados estruturados e enriquecidos com metadados geográficos e de inteligência (Shodan), tornando-os consultáveis e analisáveis.
- O fluxo principal é sequencial e baseado em stdin/stdout: cada script lê da entrada padrão e escreve na saída padrão, permitindo encadeamento via pipe no shell.
- Os `.gz` são as capturas em si. Os `.txt` são os metadados anexos.

### Arquivos do pipeline principal (`src/`)

- `0_select_representative_subset.py`: Etapa opcional para desenvolvimento. Seleciona um subconjunto representativo de capturas **brutas** a partir da nomenclatura (`<região><az>-<IP>-<data>-<hora>`), com estratificação por região e seleção sistemática temporal; cria links simbólicos no diretório de saída + `subset_manifest.{csv,json}`. Aplica-se ao `datasets/e3` atual (capturas brutas com nomenclatura padrão) — ver `contexto/dataset_e3.md`.

- `1_generate_tshark_csv.sh`: Ponto de entrada. Lê os arquivos `.pcap.gz` do diretório, descomprime cada um com `zcat` e usa o `tshark` lendo do stdin (`tshark -r -`) para extrair campos relevantes de cada pacote (timestamp, IP origem, IP destino, porta TCP/UDP, flags TCP, tipo ICMP), gerando um CSV compactado (`output.csv.gz`). O descompressor existe porque o tshark 4.6.7 falha ao abrir `.pcap.gz` diretamente (erro enganoso de permissão).

- `2_enrich_csv.py`: Recebe o CSV do passo anterior e enriquece cada linha com dados de geolocalização (via MaxMind GeoIP2) para o IP de origem e destino, e identifica a região AWS do IP de destino (via `awsipranges`). É o enriquecimento base do pipeline original. IPs fora da base GeoIP recebem fallback (`ZZ`/`ZZ Country`/região `Unknown`) sem interromper o processo; linhas que não passam no "DIRTY IP CHECK" (7 campos e IPs com 4 octetos — ex.: pacotes multi-camada IP) são descartadas para `logs/anomalous_entries.csv`, e janelas de exclusão vão para `logs/trimmed_entries.csv`.

- `3_summarize_radiation.py`: Consumidor paralelo do CSV enriquecido. Gera tabelas estatísticas em formato LaTeX com rankings de protocolos, portas, países de origem/destino, regiões AWS, etc. Usado para produzir as tabelas do TCC.

- `4_generate_graph.py`: Consumidor paralelo alternativo. Gera queries Cypher para importação no Neo4j, representando IPs de origem e destino como nós e pacotes como arestas de um grafo.

- `5_import_mysql.py`: Consumidor paralelo alternativo. Importa o CSV enriquecido para um banco MySQL/MariaDB, estruturando os dados em tabela relacional para consultas SQL.

- `6_shodan_enrich.py`: Extensão desenvolvida neste TCC. Recebe o CSV enriquecido pelo passo 2, consulta a API do Shodan para cada IP de origem (após validar que é um IPv4 válido; linhas malformadas são descartadas com log) e adiciona 10 campos ao CSV: organização, ISP, ASN, OS, portas abertas, CPEs, CVEs, tags, hostnames e data do último scan. Implementa cache local em JSON (`logs/shodan_cache.json`) enxuto — sem banners/serviços brutos — gravado em lote a cada N IPs novos (`--cache-save-every`, padrão 500) e ao final da execução; rate-limit configurável (`--rate-limit`, padrão 1s), retentativas limitadas tanto para falhas de rede (backoff exponencial) quanto para rate limit (pausa fixa de 60s, até 3x). Modos auxiliares: `--info` (grátis), `--demo <IP>` (1 consulta por execução) e `--json`.

### Arquivos de suporte

- `other/`: Scripts auxiliares que não fazem parte do fluxo principal: agregar PCAPs de múltiplas regiões, gerar estatísticas de captura (`capinfos`), importar PCAPs no SecurityOnion, processar regiões individualmente.
	- `aggregate_pcaps.sh`: faz a agregação dos `.gz` para `.txt`
	- `generate_capinfos.sh`: Opcional após rodar o script acima. Serve para extrair dos arquivos `gz`: quantos pacotes estão compactados, quando a captura começou, quando a captura terminou e qual foi a taxa média de pacotes (largura de banda)
	- `capinfos_packet_count.sh`: Também opcional, após rodar o `generate_capinfos.sh`, entra em cada um dos 26 *capinfos* gerados e soma a quantidade de pacotes que estão ali
		- `full_etl.sh`: facilitador para rodar o pipeline principal por inteiro (etapas 1→2→3→6, com 0/4/5 opcionais). Cada execução cria um novo diretório `datasets/execucao_pipeline_<origem>_<data_hora>` (o dataset de origem só é lido, via links simbólicos) e nunca altera execuções anteriores. Opções: `-d/--dataset` (origem, padrão `datasets/e3`), `-n/--num-pcaps N` (usa a etapa 0 para selecionar até N capturas; padrão: todas), `-q/--shodan-queries N` (alimenta a etapa 6 só com as N primeiras linhas do CSV enriquecido), `--with-neo4j` (gera `output_neo4j.cypher`, requer os `enriched_unique_*_IPs.csv` na raiz) e `--with-mysql` (importa no banco, requer credenciais em `src/5_import_mysql.py`). `.csv`, LaTeX e Shodan são sempre gerados; valida pré-requisitos (tshark, dependências Python, `SHODAN_API_KEY`) antes de iniciar e, após a etapa 2, emite aviso quando 100% dos destinos caem no fallback GeoIP/AWS (coluna M = ZZ; causa típica: destinos privados). Detalhes e testes: `tests/exemplos_de_testes.md` e `contexto/implementacoes_e_testes.md`.
	- `import_pcaps_onto_securityonions.sh`: Opcional: automação para importar os `pcaps` para dentro do *securityonion*
	- `testawsranges.py`: testa se um determinado arquivo `csv` gerado pelo pipeline de fato contem IPs de destino que pertencem a AWS.
	
- `tests/`: Scripts de prova de conceito usados durante o desenvolvimento para explorar a resposta da API do Shodan antes de integrar ao pipeline.

- `Docker/`: `docker-compose.yml` e `Dockerfile` para rodar o pipeline e o banco MySQL em containers.

- `datasets/e3`: Capturas brutas coletadas pelo Cloud Telescope, com nomenclatura padrão `<região><az>-<IP>-<YYYYMMDD>-<HHMM>.pcap.gz` (~21.300 capturas, ~42.600 arquivos incluindo `.pcap.txt`). Dataset-alvo deste TCC (outubro/2023 a fevereiro/2024).
