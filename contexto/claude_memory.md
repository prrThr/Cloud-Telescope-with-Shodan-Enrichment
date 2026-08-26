# Memória de sessões anteriores — ibr-etl

> **Status:** registro histórico auxiliar, **não-canônico**. Em conflito com código,
> testes ou documentos vivos (`AGENTS.md`, `contexto/pipeline.md`,
> `contexto/estrutura.md`, `contexto/dataset_e3.md`), investigue antes de decidir.
> Última revisão deste arquivo: 2026-08-23.

## Propósito e contexto

Arthur desenvolve o "Cloud Telescope", pipeline de análise de tráfego de rede, como
TCC de graduação. O projeto processa arquivos pcap por um ETL, aplicando
enriquecimento geográfico e técnico aos dados de tráfego. O TCC formaliza o trabalho
com requisitos funcionais (RF01–RF07), não funcionais (RNF01–RNF05) e casos de uso
(CSU01–CSU03).

Áreas de domínio: análise de tráfego de rede, processamento de capturas de pacotes,
integração com APIs, enriquecimento de dados, bancos de grafos e apresentação de
pesquisa acadêmica.

## Estado atual

O pipeline (ibr-etl) foi reorganizado para portabilidade e replicabilidade:

- Scripts do pipeline movidos para `src/`, datasets para `datasets/`, Docker para `Docker/`.
- Todos os scripts padronizados a derivar `PROJECT_ROOT` do próprio caminho de arquivo
  (padrão `os.path.dirname`), eliminando dependência do diretório de trabalho ou `cd`.
- Módulo de enriquecimento Shodan (`src/6_shodan_enrich.py`) construído e validado,
  estendendo o CSV enriquecido com 10 campos Shodan (organização, ISP, ASN, OS,
  portas abertas, CPEs, CVEs, tags, hostnames, last-seen).
- Correções pós-banca registradas em `contexto/implementacoes_e_testes.md`
  (retry limitado, cache enxuto, gravação em lote, validação IPv4, workaround tshark).
- A API key hardcoded foi identificada e **corrigida** — segredos agora vivem em `.env`.

Fluxo do pipeline: `1_generate_tshark_csv.py` → `2_enrich_csv.py` →
`6_shodan_enrich.py` → consumidores paralelos (`3_summarize_radiation.py`,
`4_generate_graph.py`, `5_import_mysql.py`) → visualizações comparativas (planejadas).
As etapas 3–5 consomem o mesmo CSV enriquecido em paralelo, não sequencialmente.

## No horizonte

- Visualizações comparativas de ganho informacional (etapa final planejada).
- Possível diagrama ramificado do pipeline para representar o paralelismo das etapas 3–5.
- Implementação plena de todos os requisitos do TCC além da base Shodan atual.

## Lições e princípios-chave

- Scripts devem resolver caminhos relativos à raiz do projeto, nunca ao diretório de
  trabalho, para garantir replicabilidade entre máquinas.
- Conservação dos créditos da API Shodan é restrição real: cache por IP (JSON local)
  e rate limiting (1 req/s padrão, backoff em 429) são decisões essenciais de design,
  não opcionais.
- O pipeline segue um padrão consistente de stdin/stdout CSV entre scripts, que deve
  ser preservado em módulos novos.
- Scripts redundantes devem ser consolidados, não mantidos em paralelo.
- Datasets completos não são explorados diretamente: entende-se sua estrutura pela
  documentação e pelas regex de nomenclatura; testes usam amostras pequenas.

## Ferramentas e recursos

- Stack principal: Python, Bash, tshark (extração de pacotes), GeoIP2-City (MaxMind
  licenciada), API Shodan, Neo4j (grafo Cypher), MySQL.
- Infraestrutura: Docker / docker-compose.
- Formatos de dados: pcap → CSV → CSV enriquecido (`.enriched.csv.gz`, `.shodan.gz`)
  → Neo4j / MySQL.
- Documento de tese: `contexto/TCC_2_ArthurPereira_PosBanca.md`, usado como
  especificação viva para alinhamento do desenvolvimento.
