# ibr-etl — Cloud Telescope / Internet Background Radiation (IBR)

Pipeline de ETL que processa capturas de tráfego de rede (Internet Background Radiation,
"radiação de fundo" da internet) coletadas pelo telescópio Cloud Telescope — PCAPs de
honeypots em instâncias AWS — e as enriquece com dados geográficos (GeoIP), infraestrutura
AWS (awsipranges) e metadados OSINT (Shodan). É o projeto de TCC de Arthur Pereira, que
estende o trabalho original do prof. Fabrício Bortoluzzi.

## CRÍTICO — nunca escaneie/leia o diretório `datasets/`

`datasets/` contém ~37 GiB de capturas binárias (`.pcap.gz` do `tcpdump`). São arquivos
**opacos e binários** — você não precisa e não deve ler o conteúdo de nenhum deles.

- NÃO execute `ls`, `find`, `glob`, `du`, `rg`, `read` ou qualquer outra operação que
  liste, conte ou abra arquivos dentro de `datasets/` (nem em `datasets/e1`,
  `datasets/e3`, nem em qualquer subdiretório criado por processamento).
- Os arquivos já estão no `.gitignore`; as ferramentas de listagem do opencode também os
  ignoram. Só tenha cuidado com comandos `bash` crus, que não respeitam o `.gitignore`.
- Para entender a **estrutura/forma** dos arquivos, use:
  - a regra de nomenclatura documentada abaixo;
  - o parser de nomes em `src/0_select_representative_subset.py` (a regex `FILENAME_RE`);
  - o contexto em `contexto/estrutura.md`.
- Se um comando de leitura sobre um `.pcap.gz` for absolutamente inevitável (ex: você foi
  instruído a inspecionar um arquivo específico), use `zcat <arquivo> | head -c <bytes>` e
  limite a < 1 MB.

### Nomenclatura dos arquivos de captura

```
<região>-<az>-<IP>-<YYYYMMDD>-<HHMM>.pcap.gz
```

Exemplo: `af-south-1b-13.244.71.194-20230501-1217.pcap.gz`
→ região `af-south-1`, AZ `b`, IP `13.244.71.194`, captura de `2023-05-01 12:17`.

- No Dataset 1 (`e1`) o nome combina região+AZ diretamente: `af-south-1b-...` (região
  `af-south-1` + AZ `b`). Veja `REGION_AZ_RE` em `src/0_select_representative_subset.py`.
- Pode haver variantes com `-`/`_` como separadores e sufixos `.pcap.txt` (dump textual
  do mesmo pcap).

### Datasets

- `datasets/e1` — Dataset 1: ~4.600 capturas pequenas, estratificadas por região.
- `datasets/e3` — Dataset 3: ~29 capturas agregadas por região + `final_results/` (~17 GiB
  de resultados de processamento).
- `datasets/e1/aggregated` e `datasets/e3/final_results` são saídas de processamento;
  também não devem ser lidas/escaneadas.

## Contexto do projeto (leia antes de qualquer modificação)

Os documentos canônicos ficam em `contexto/` (são o "living spec" do TCC):

- `contexto/Cloud_Telescope.md` — TCC do prof. Bortoluzzi (base do projeto).
- `contexto/TCC_2_ArthurPereira_PosBanca.md` — TCC do Arthur (especificação a seguir).
- `contexto/claude_memory.md` — memória/lições de sessões anteriores.
- `contexto/estrutura.md` — árvore de arquivos do projeto.
- `contexto/instrucoes.md` — instruções de contexto para agentes de IA.

Os dois primeiros são grandes; leia-os seletivamente (grep/parágrafos) conforme a tarefa,
não do início ao fim.

## Estrutura do repositório

- `src/` — pipeline principal (ver abaixo). Todos os scripts derivam `PROJECT_ROOT` do
  próprio caminho; não dependem do diretório de trabalho.
- `contexto/` — documentação/TCC.
- `other/` — utilitários auxiliares (agregação de pcaps, ETL completo, por região).
- `backups/` — **inútil, ignore.**
- `logs/` — saídas de log/cache de execuções (ex: `shodan_cache.db`, `cacheinfo.txt`).
- `Docker/` — `Dockerfile` + `docker-compose.yml`.
- `tests/` — testes/POCs do módulo Shodan.
- `venv/` — ambiente virtual local (ignore).
- `GeoLite2-City.mmdb` / `GeoIP2-City.mmdb` — base MaxMind GeoIP (licenciada vs. gratuita).

## Pipeline

Fluxo: extração (tshark) → enriquecimento (GeoIP + AWS) → enriquecimento Shodan →
consumidores paralelos (resumo, grafo, MySQL).

| Etapa | Arquivo | Entrada → Saída |
|---|---|---|
| 0. Amostragem | `src/0_select_representative_subset.py` | seleciona subconjunto representativo do dataset (estratificação por região + seleção sistemática), cria `subset_manifest.{csv,json}` |
| 1. Extração | `src/1_generate_tshark_csv.sh` | `dir/*.pcap.gz` → `dir/output.csv.gz` (colunas `time,ip.src,ip.dst,tcp.dstport,tcp.flags.str,udp.dstport,icmp.type`) |
| 2. Enriquecimento | `src/2_enrich_csv.py` | `output.csv.gz` → `output.enriched.csv.gz` (adiciona GeoIP de origem e destino + região AWS; descarta janelas de exclusão) |
| 3. Resumo | `src/3_summarize_radiation.py` | `output.enriched.csv.gz` → `output.tex` (agregações de radiação) |
| 4. Grafo | `src/4_generate_graph.py` | CSV de IPs únicos → Cypher para Neo4j |
| 5. MySQL | `src/5_import_mysql.py` | CSV enriquecido → banco MySQL |
| 6. Shodan | `src/6_shodan_enrich.py` | `output.enriched.csv.gz` → `output.shodan.gz` (campos 18–27: org, ISP, ASN, OS, portas, CPEs, CVEs, tags, hostnames, last_seen) |

As etapas 3–5 consomem o mesmo CSV enriquecido **em paralelo** (não sequencialmente).
A etapa 6 adiciona campos nas posições 18–27 do CSV (após `awsregion`).

### Exemplos de execução

```sh
python3 src/0_select_representative_subset.py datasets/e3 --output datasets/e3_subset --max-files 48 --clean
src/1_generate_tshark_csv.sh datasets/e3_subset
zcat datasets/e3_subset/output.csv.gz | python src/2_enrich_csv.py | gzip > datasets/e3_subset/output.enriched.csv.gz
zcat datasets/e3_subset/output.enriched.csv.gz | python src/6_shodan_enrich.py | gzip > datasets/e3_subset/output.shodan.gz
zcat datasets/e3_subset/output.enriched.csv.gz | python src/3_summarize_radiation.py > datasets/e3_subset/output.tex
```

## Convenções de código

- Contrato de pipeline: **stdin/stdout com CSV** — cada etapa lê CSV da entrada padrão e
  emite CSV (compactado com `gzip`) na saída padrão. Preserve isso em novos módulos.
- Todos os scripts resolvem caminhos relativos ao `PROJECT_ROOT` (via
  `os.path.dirname(os.path.dirname(os.path.abspath(__file__)))`), nunca ao CWD.
- Código e comentários em português (padrão do repositório).
- Sem comentários adicionais em código novo, a menos que solicitado.

## Segurança e credenciais

- `.env` contém segredos (`SHODAN_API_KEY`). NUNCA comite, logue ou exponha segredos.
- Créditos da API Shodan são limitados: cache local por IP (`shodan_cache.db`) e
  rate-limit (1 req/s, com backoff em 429) são decisões de design, não opcionais.
- O hardcoded de API key foi corrigido; não reintroduza chaves no código.

## Verificação

Não há framework de lint/test padronizado no projeto. Verifique mudanças executando o
script/pipeline afetado com uma amostra pequena (ex: `--max-files 12`), como nos exemplos
acima. Antes de executar pipelines, remova `output*.csv*` antigos do diretório de destino.

## Idioma

Comunique-se com o usuário em português.
