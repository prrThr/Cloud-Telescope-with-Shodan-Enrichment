# ibr-etl — Cloud Telescope / Internet Background Radiation (IBR)

Pipeline de ETL que processa capturas de tráfego de rede (Internet Background Radiation,
"radiação de fundo" da internet) coletadas pelo telescópio Cloud Telescope — PCAPs de
honeypots em instâncias AWS — e as enriquece com dados geográficos (GeoIP), infraestrutura
AWS (awsipranges) e metadados OSINT (Shodan). É o projeto de TCC de Arthur Pereira, que
estende o trabalho original do prof. Fabrício Bortoluzzi.

## CRÍTICO — leia `contexto/instrucoes.md` antes de modificar o projeto

`contexto/instrucoes.md` contém as instruções específicas para agentes de IA trabalharem
neste projeto.

Antes de realizar qualquer modificação significativa:

1. Leia `contexto/instrucoes.md`.
2. Consulte os documentos de referência indicados nesse arquivo.
3. Consulte `contexto/estrutura.md` para compreender a organização atual.
4. Consulte `contexto/pipeline.md` para compreender o pipeline atual.
5. Verifique o código existente antes de propor uma nova implementação.
6. Não faça alterações baseadas apenas em suposições.

As instruções de `contexto/instrucoes.md` complementam este arquivo.

Em caso de conflito, preserve as regras de segurança, integridade dos dados e
credenciais definidas neste `AGENTS.md`.

## Datasets

Os datasets estão disponíveis em:

- `datasets/e1` — Dataset 1.
- `datasets/e3` — Dataset 3.

Os datasets possuem grande volume de dados e não devem ser lidos ou processados
integralmente apenas para compreender sua estrutura.

A inspeção inicial dos datasets deve seguir estritamente as regras de
`contexto/instrucoes.md`.

### Regra geral

- Não leia todos os arquivos dos datasets.
- Não percorra desnecessariamente grandes volumes de dados.
- Não processe os datasets completos durante testes de desenvolvimento.
- Prefira amostras pequenas e representativas.
- Não leia ou escaneie `datasets/e1/aggregated` ou `datasets/e3/final_results`
  sem necessidade explícita.

### Nomenclatura das capturas

A nomenclatura padrão é:

```
<região>-<az>-<IP>-<YYYYMMDD>-<HHMM>.pcap.gz
```

Exemplo: `af-south-1b-13.244.71.194-20230501-1217.pcap.gz`

Representa:
região: `af-south-1`
Availability Zone: `b`
IP: `13.244.71.194`
data: `2023-05-01`
horário: `12:17`


No Dataset 1 (`e1`), região e AZ aparecem combinadas no nome, como `af-south-1b`.
Consulte `src/0_select_representative_subset.py`, especialmente `FILENAME_RE` e
`REGION_AZ_RE`, quando precisar compreender ou alterar o parser dos nomes.

### Coletas atuais

- `datasets/e1` — Dataset 1: ~2.300 capturas brutas `.pcap.gz` (≈4.600 arquivos com os
  `.pcap.txt`), estratificadas por região, + `aggregated/` (26 consolidados por região).
- `datasets/e3` — Dataset 3: 26 arquivos agregados por região (`e3_<região>.pcap.gz`)
  + `capinfos/` + `final_results/` (~17 GiB de resultados de processamento anterior).
  `aggregated/` (e1) e `final_results/` (e3) não devem ser lidos/escaneados sem
  necessidade explícita. Diferenças e uso: `contexto/e1_vs_e3.md`.

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

- `src/` — pipeline principal
- `contexto/` — documentação, TCC e instruções do projeto
- `other/` — utilitários auxiliares (agregação de pcaps, ETL completo, por região).
- `backups/` — **inútil, ignore completamente.**
- `logs/` — saídas de log e cache de execuções (ex: `shodan_cache.json`, `cacheinfo.txt`).
- `Docker/` — `Dockerfile` + `docker-compose.yml`.
- `tests/` — testes e provas de conceito.
- `venv/` — ambiente virtual local (ignore).
- `GeoLite2-City.mmdb` / `GeoIP2-City.mmdb` — base MaxMind GeoIP (licenciada vs. gratuita).

Todos os scripts do pipeline devem resolver caminhos relativos ao `PROJECT_ROOT` e não depender do diretório de trabalho atual.

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
python3 src/0_select_representative_subset.py datasets/e1 --output datasets/e1_subset --max-files 48 --clean
src/1_generate_tshark_csv.sh datasets/e1_subset
zcat datasets/e1_subset/output.csv.gz | python src/2_enrich_csv.py | gzip > datasets/e1_subset/output.enriched.csv.gz
zcat datasets/e1_subset/output.enriched.csv.gz | python src/6_shodan_enrich.py | gzip > datasets/e1_subset/output.shodan.gz
zcat datasets/e1_subset/output.enriched.csv.gz | python src/3_summarize_radiation.py > datasets/e1_subset/output.tex
```

> A etapa 0 exige a nomenclatura bruta (`<região><az>-<IP>-<data>-<hora>`) e deve rodar
> sobre `datasets/e1`. Os agregados do `datasets/e3` (`e3_<região>.pcap.gz`) não são
> elegíveis para amostragem — na produção, consuma-os diretamente na etapa 1. Detalhes:
> `contexto/e1_vs_e3.md`.

## Contrato de pipeline
- **stdin/stdout com CSV** — cada etapa lê CSV da entrada padrão e emite CSV (compactado com `gzip`) na saída padrão. Preserve isso em novos módulos.
- Os scripts devem resolver caminhos relativos ao `PROJECT_ROOT`, nunca ao `CWD`.

## Convenções de código

- Todos os scripts resolvem caminhos relativos ao `PROJECT_ROOT` (via `os.path.dirname(os.path.dirname(os.path.abspath(__file__)))`), nunca ao `CWD`.
- Código e comentários em português (padrão do repositório).
- Sem comentários adicionais em código novo, a menos que solicitado.
- Preserve o estilo e a arquitetura existentes.
- Evite refatorações não relacionadas à tarefa solicitada.
- Antes de criar uma nova abstração, verifique se já existe uma implementação equivalente.
- Não altere contratos de entrada/saída sem verificar todos os consumidores afetados.

## Segurança e credenciais

- `.env` contém segredos (`SHODAN_API_KEY`). NUNCA comite, logue ou exponha segredos.
- Créditos da API Shodan são limitados: cache local por IP (`logs/shodan_cache.json`, gravado em lote via `--cache-save-every`) e rate-limit (1 req/s, com retentativas limitadas) são decisões de design, não opcionais.
- O hardcoded de API key foi corrigido; não reintroduza chaves no código.

## Verificação

Não há framework de lint/test padronizado no projeto. Verifique mudanças executando o script/pipeline afetado com uma amostra pequena (ex: `--max-files 12`), como nos exemplos acima. Antes de executar pipelines, remova `output*.csv*` antigos do diretório de destino.

Os comandos de teste para a situação atual do pipeline estão documentados em
`tests/exemplos_de_testes.md`. **Mantenha esse arquivo atualizado** sempre que o
pipeline mudar (novas etapas, argumentos, formatos de CSV/cache, modos de uso) —
corrija exemplos desatualizados em vez de ignorá-los.

## Documentação

Sempre que uma implementação alterar o comportamento do projeto:

1. atualize a documentação correspondente;
2. atualize `contexto/pipeline.md` se uma etapa do pipeline tiver sido alterada;
3. registre os testes realizados e seus resultados em documentação dentro de `contexto/`, conforme `contexto/instrucoes.md`.

Não considere uma implementação concluída enquanto os testes necessários e sua
documentação não tiverem sido realizados.

## Git

- Não faça commits automaticamente, a menos que o usuário solicite explicitamente.
- Não reverta alterações existentes sem verificar se elas pertencem ao trabalho atual.
- Preserve alterações feitas anteriormente pelo usuário ou por outros agentes.

## Idioma

Comunique-se com o usuário em português.
