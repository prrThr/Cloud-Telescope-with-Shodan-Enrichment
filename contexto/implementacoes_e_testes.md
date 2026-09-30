# Registro de implementações e testes — correções pós-banca

Registro das implementações realizadas nas etapas 1, 2 e 6 do pipeline, seguindo o
formato exigido por `contexto/instrucoes.md` (seção 7), com distinção explícita entre
resultado esperado e resultado obtido (seção 10).

---

## L. Imagens limpas na etapa 7 (sem "Sem registro"/"não consultados"), ganho informacional e `--cache-only` na etapa 6

### Objetivo

As imagens `os_distribution.png`, `org_ranking.png` e `isp_ranking.png` eram
dominadas pelas categorias "Sem registro" e "não consultados" (a esmagadora
maioria dos IPs, pois o Shodan só enriquece um subconjunto), tornando-as
ilegíveis. O objetivo é gerar as visualizações **sem** esses dados não
coletados, usando o cache Shodan (`found=true`) como fonte de verdade, e
permitir comparar as duas coletas ("sem Shodan" vs "com Shodan"). O
`comparacao_pipeline.png` (1,3% vs 98,7%) foi considerado inútil e removido,
sendo substituído por uma análise explícita de **ganho informacional**
(`ganho_shodan`), que responde ao objetivo central do TCC: o que o Shodan
adicionou ao ETL. Adicionalmente, a etapa 6 ganhou `--cache-only` para regenerar
o CSV de 28 colunas refletindo **apenas** o cache acumulado, sem gastar créditos.

### Alterações realizadas

- `src/7_analyze_results.py`:
  - Novo flag reverso `--incluir-nao-enriquecidos` (restaura o comportamento
    antigo). Por padrão, a análise é restrita aos IPs com `found=true` no cache.
  - `main` lê o cache e o universo (`--original-csv` ou os IPs do CSV) no início,
    calcula o conjunto `com_dados` e filtra `df` para esses IPs antes das análises
    (OS/org/ISP/portas/CVEs/geo×OS). Se não houver nenhum IP enriquecido, emite
    aviso e mantém o comportamento antigo.
  - `contagem_por_campo` ganhou `drop_empty=True` (descarta campos vazios em vez
    de rotular "Sem registro"), repassado por `salvar_analise_por_campo`.
  - `plot_barras` trata DataFrame vazio (sem crash).
  - `analisar_comparacao` ganhou `detalhado`; por padrão compara **duas
    categorias** — "Com Shodan (enriquecidos)" vs "Sem Shodan (não
    enriquecidos)". A geração do `comparacao_pipeline.png` (e a função
    `plot_comparacao`) foi **removida**; resta o CSV e o resumo no terminal.
  - Nova análise `analisar_ganho` (+ constante `CAMPOS_GANHO`): gera
    `ganho_shodan.{csv,png}`, com a contagem de IPs enriquecidos que possuem cada
    metadado adicionado pelo Shodan (org, ISP, ASN, OS, portas, CPEs, CVEs,
    tags, hostnames) — os campos que não existiam no ETL original. O título do
    gráfico é "Ganho do enriquecimento Shodan — N IPs enriquecidos de TOTAL".
  - Nova análise `analisar_tags`: gera `tags_distribuicao.{csv,png}` com a
    contagem de IPs únicos por tag Shodan, destacando cloud/vpn/tor/proxy no
    gráfico (`plot_barras` ganhou o parâmetro `destaques`).
  - `read_csv_from_stdin` passou a **deduplicar por `ip.src`** durante a leitura
    (memória proporcional ao nº de IPs únicos, não ao de linhas); linhas com nº
    de campos ≠ 28 são ignoradas/contabilizadas. `ler_ips_originais` extrai o 2º
    campo sem fatiar a linha inteira. `imprimir_contagem` e o resumo do
    `geo_os_cross` limitam a saída ao top 20 (antes despejavam todas as
    categorias/portas no terminal).
    Sem isso, rodar sobre `output.shodan.csv.gz` do `e3_full` (98.032.823 linhas)
    era morto por OOM.
- `src/6_shodan_enrich.py`: novo flag `--cache-only` (e parâmetro
  `cache_only` em `process_pipeline`); IPs ausentes do cache recebem campos
  vazios via `_empty_record(..., reason="not_queried_cache_only")` sem consultar
  a API, com novo contador `not_queried` no relatório.
- Documentação: `contexto/pipeline.md` (etapas 6 e 7), `contexto/guia_execucao.md`
  (seções 5.2/5.3/5.4) e `tests/exemplos_de_testes.md`.

### Comportamento esperado

- Padrão: `os_distribution`/`org_ranking`/`isp_ranking` **sem** "Sem registro";
  `comparacao_pipeline` com duas linhas (Com/Sem Shodan); `ganho_shodan` com os
  9 metadados adicionados pelo Shodan.
- `--incluir-nao-enriquecidos`: comportamento antigo (categoria "Sem registro" e
  três categorias de cobertura).
- `--cache-only`: zero `API calls`; IPs fora do cache saem com campos Shodan vazios.

### Testes realizados e resultados

Fixtures sintéticas em `/tmp/opencode/t7test` (4 linhas de 28 colunas; cache com
`1.1.1.1` found=true, `2.2.2.2` found=false, `4.4.4.4` found=true sem OS;
universo de 5 IPs via `orig.csv`).

Resultado esperado (padrão): `os_distribution` só `Linux` (1); `org_ranking`
`Org A`/`Org B`; `isp_ranking` `ISP A`/`ISP B`; `comparacao_pipeline`
`Com Shodan=2` / `Sem Shodan=3`.

Resultado obtido: conforme esperado — sem "Sem registro" nos rankings; comparação
`Com Shodan (enriquecidos),2,40.0` e `Sem Shodan (não enriquecidos),3,60.0`.
Com `--incluir-nao-enriquecidos`, "Sem registro" reaparece (OS 3/75%) e a
cobertura volta a 3 categorias (com dados 2 / sem dados 1 / não consultados 2).

Teste do `--cache-only` (etapa 6): com cache de 2 IPs e 3 linhas de entrada,
`status=concluido`, `API calls: 0`, `IPs não consultados: 1`; a linha do IP
found=true saiu enriquecida e as demais com campos vazios.

### Teste em dados reais (`e3_full`, cache acumulado pela rotação)

Comando executado no diretório
`datasets/rotacao_shodan_e3_full_20260919_103421` (cache de 32.645 IPs):

```sh
DIR=datasets/rotacao_shodan_e3_full_20260919_103421
# universo dedup por IP de origem (18 col) — feito uma vez (~1m15s)
zcat "$DIR/output.enriched.csv.gz" | awk -F, '!seen[$2]++' | gzip > "$DIR/output.enriched.unique.csv.gz"
# regenera o 28-col só com o cache (zero créditos, ~5s)
zcat "$DIR/output.enriched.unique.csv.gz" | venv/bin/python src/6_shodan_enrich.py --cache-only | gzip > "$DIR/output.shodan.unique.csv.gz"
# imagens
zcat "$DIR/output.shodan.unique.csv.gz" | venv/bin/python src/7_analyze_results.py \
    --original-csv "$DIR/output.enriched.unique.csv.gz" --cache-file logs/shodan_cache.json --output-dir "$DIR"
```

Resultado obtido:
- entrada de 98.032.823 linhas → 724.400 IPs únicos (10 linhas malformadas
  ignoradas); sem OOM.
- `--cache-only`: `Cache hits: 28.936`, `API calls: 0`.
- `comparacao_pipeline.csv`: `Com Shodan (enriquecidos)=9.396 (1,3%)` e
  `Sem Shodan (não enriquecidos)=715.014 (98,7%)`.
- `os_distribution`/`org_ranking`/`isp_ranking` sem "Sem registro" (0
  ocorrências); PNGs regenerados.
- `ganho_shodan.csv` (9.394 IPs enriquecidos com metadados): Organização 100%,
  ISP 100%, Portas abertas 100%, ASN 99,83%, CPEs 66,65%, Tags 57,35%,
  Hostnames 56,47%, CVEs 20,96%, Sistema operacional 15,73%.
- `tags_distribuicao.csv` (dentre os 9.394 enriquecidos): cloud 2.986 (31,8%),
  scanner 1.966 (20,9%), eol-product 793 (8,4%), vpn 211 (2,3%), honeypot 155,
  proxy 86, tor 9.
- `comparacao_pipeline.png` removido; `ganho_shodan.png` e
  `tags_distribuicao.png` gerados.

### Problemas ou limitações

- O filtro depende do cache (`found=true`). Sem cache (ou sem IPs com dados), a
  etapa 7 emite aviso e mantém o comportamento antigo.
- `geo_os_cross.csv` continua usando `df_analise`, mas ainda rotula como "Sem
  registro" um IP enriquecido cujo OS seja genuinamente vazio (não é imagem-alvo
  desta mudança).
- A regeneração do 28-col via `--cache-only` ainda executa `init_api` (1 chamada
  `api.info()`, gratuita), pois a etapa 6 valida a chave antes do loop.

---

## K. Correções nas etapas 1, 2, 3 e 4 (`src/`)

### Objetivo

Corrigir defeitos identificados na análise do pipeline, sem alterar os contratos
stdin/stdout nem o formato dos CSVs (7/18/28 colunas):

- **Etapa 1** (`1_generate_tshark_csv.py`): o flag `--max-files` colidia
  conceitualmente com o `--max-files` (estratificado) da etapa 0; e a constante
  `PROJECT_ROOT` era calculada mas nunca usada.
- **Etapa 2** (`2_enrich_csv.py`): `logs/trimmed_entries.csv` era aberto a cada
  execução e nunca escrito (arquivo vazio enganoso, feature nunca implementada).
- **Etapa 3** (`3_summarize_radiation.py`): um `print` do dicionário
  `merged_source_country_transport_layer` e os `print` de `Sub-total`/`Total` dentro
  de `dumpdict` poluíam o `output.tex` (misturados às tabelas LaTeX); o dump era
  aberto em modo append, acumulando entre execuções.
- **Etapa 4** (`4_generate_graph.py`): os `enriched_unique_*_IPs.csv` eram abertos
  por caminho relativo (dependente do CWD) e o mapeamento de colunas do CSV
  enriquecido no stdin estava deslocado a partir do índice 4 (tratava
  `tcp.flags.str` como `udp.dstport`), classificando mal o protocolo.

### Alterações realizadas

- `src/1_generate_tshark_csv.py`: removido `PROJECT_ROOT` (não usado); flag
  `--max-files` renomeado para `--max-pcap-files` (variável `max_pcap_files`); exemplo
  do help atualizado (`e1_subset` → `e3_subset`).
- `src/2_enrich_csv.py`: removidos a abertura e o fechamento de `trimmed_entries`.
- `src/3_summarize_radiation.py`: removido o `print(merged_source_country_transport_layer)`;
  `dumpdict` agora grava `Sub-total`/`Total` no arquivo (`f.write`, antes `print` no
  stdout) e o dump é aberto uma vez em modo `w` (idempotente), com `dump_file.close()`
  ao final.
- `src/4_generate_graph.py`: adicionado `PROJECT_ROOT` e os dois arquivos de IPs
  únicos passam a ser abertos via `os.path.join(PROJECT_ROOT, ...)`; corrigidos os
  índices das colunas do stdin para o CSV de 18 colunas (`udpdstport=line[5]`,
  `icmptype=line[6]`, ..., `aws_region=line[17]`).
- Documentação: `contexto/pipeline.md` (etapa 1 `--max-pcap-files`; etapa 2 sem
  `trimmed_entries`; etapa 4 com entradas da raiz), `contexto/estrutura.md` (remove
  `logs/trimmed_entries.csv`) e `tests/exemplos_de_testes.md` (reconciliação
  `entrada = enriquecidas + anomalous_entries`; nota sobre o dump da etapa 3; etapa 4
  com caminhos do `PROJECT_ROOT`).

### Comportamento esperado

- Etapa 1: `--max-pcap-files N` limita arquivos sem estratificação; `--max-files`
  passa a ser exclusivo da etapa 0.
- Etapa 2: `logs/trimmed_entries.csv` não é mais criado.
- Etapa 3: `output.tex` contém apenas LaTeX; `logs/summarize_radiation_dict_dump.txt`
  tem tamanho estável entre execuções.
- Etapa 4: roda de qualquer CWD e classifica corretamente TCP/UDP/ICMP.

### Testes realizados e resultados

| Teste | Resultado esperado | Resultado obtido |
|---|---|---|
| `py_compile` dos 4 módulos | compilam | OK |
| Etapa 1 `--help` | exibe `--max-pcap-files`, sem `--max-files` | OK |
| Etapa 1 `--max-pcap-files 1` (2 pcaps sintéticos) | processa 1 arquivo, `output.csv.gz` com 1 linha | OK |
| Etapa 1 `--max-files 1` | rejeitado (unrecognized arguments, exit 2) | OK |
| Etapa 2 sobre CSV bruto sintético (2 linhas) | exit 0; 18 colunas; `logs/trimmed_entries.csv` ausente | OK |
| Etapa 3 vs versão anterior (3 linhas sintéticas) | sem dict (`{`) e sem `Sub-total`/`Total` fora do `\\` | OK — OLD: 1 dict + 40 linhas vazadas (+40 em branco) = 81 linhas extras; NEW: 0 |
| Etapa 3 idempotência do dump | mesmo nº de linhas nas 2 execuções | OK — 111 e 111 |
| Etapa 4 vs versão anterior (18 col: TCP/UDP/ICMP) | NEW: tcp/80, udp/53, icmp/8; OLD errava udp→icmp e icmp→unknown | OK |
| Etapa 4 a partir de `/tmp/opencode` | encontra fixtures na raiz do projeto | OK |

Testes sem gasto de créditos. Fixtures temporárias (`enriched_unique_*_IPs.csv`) e
arquivos em `/tmp/opencode` removidos ao final.

### Problemas ou limitações

- A etapa 4 segue dependendo de `enriched_unique_source_IPs.csv` /
  `enriched_unique_destination_IPs.csv`, que a etapa 2 ainda **não gera** (bloco
  comentado); o `full_etl.sh --with-neo4j` valida a presença dessas fixtures antes de
  rodar. Sem elas, a etapa 4 falha ao abrir os arquivos (comportamento pré-existente).
- O `merged_source_country_transport_layer` (usado apenas por visualizações
  comentadas) continua sendo calculado, porém sem ser impresso.
- `logs/trimmed_entries.csv` pode existir como resíduo de execuções anteriores
  (arquivo ignorado pelo git); não é mais recriado.

---

## J. `full_etl.sh` como comando canônico "execute pipeline" (etapas 0→7)

### Objetivo

Transformar o `other/full_etl.sh` no comando único de execução do pipeline, rodando
todas as etapas (0→7, incluindo a análise da etapa 7) e alinhando o flag
`-q/--shodan-queries` ao significado real de "número de consultas Shodan": até N
consultas **novas** à API (reusando `--max-new-queries` da etapa 6), em vez do
antigo limite de "N primeiras linhas".

### Alterações realizadas

- `other/full_etl.sh`:
  - `-q/--shodan-queries N` agora alimenta a etapa 6 com `--max-new-queries N`
    (consultas novas reais; cache hits não contam), em substituição ao
    `awk 'NR<=N'`. O `exit 10` (limite atingido) passou a ser tratado como parada
    graciosa (loga e retorna 0), mantendo o `output.shodan.csv.gz` íntegro e
    prosseguindo para a etapa 7.
  - Nova **etapa 7 (análise de resultados)** no fluxo, sempre executada quando
    `pandas`/`matplotlib` estão disponíveis no interpretador usado (senão, avisa e
    pula). Invoca `7_analyze_results.py --original-csv <enriquecido> --output-dir
    <execução>` (e `--cache-file`, quando informado) sobre o `output.shodan.csv.gz`.
  - Seleção do interpretador unificada: a etapa 1 agora usa `$PY` (venv) como as
    demais (antes hardcoded `python3`).
  - Novos flags de pass-through: `-c/--cache-file`, `--rate-limit`,
    `--cache-save-every` (etapa 6; o cache-file também vai para a etapa 7) e
    `--region` (fallback da etapa 2), com validação no preflight.
  - `usage()` e mensagens atualizadas (etapas 0→7, semântica de `-q`, artefatos da
    etapa 7 no resumo final).

### Comportamento esperado

- `other/full_etl.sh -d ... -q N` encerra a etapa 6 após até N consultas novas e
  gera os artefatos das etapas 0→7 (CSVs/PNGs da análise inclusos).
- `-q` ausente: etapa 6 processa todas as linhas.
- Sem `pandas`/`matplotlib`: aviso e etapa 7 pulada; demais etapas seguem.
- Flags inválidos (`-q 0`, `--rate-limit abc`, `--cache-save-every abc`) → erro no
  preflight, exit 1.

### Testes realizados e resultados

| Teste | Resultado esperado | Resultado obtido |
|---|---|---|
| `bash -n other/full_etl.sh` | sintaxe válida | OK |
| `other/full_etl.sh --help` | ajuda, exit 0, stderr vazio | OK |
| E2E offline (2 pcaps sintéticos Ethernet+IPv4+UDP, cache temporário pré-povoado com os 2 IPs de origem, `-q 2 -c <cache>`) | exit 0; 18 colunas no enriquecido; 28 no shodan; artefatos da etapa 7 presentes; 0 API calls | OK — 18/28 colunas, 2 linhas, `API calls: 0`, `os_distribution`/`org_ranking`/`isp_ranking`/`top_ports`/`port_cves`/`comparacao_pipeline`/`geo_os_cross` gerados |
| E2E com flags de pass-through (`--rate-limit 0 --cache-save-every 2 --region af-south-1`) | exit 0, execução completa | OK |
| Validação: `-q 0`, `--rate-limit abc`, `--cache-save-every abc`, `-n 0` | erro de preflight, exit 1 | OK |

Testes sem gasto de créditos (todas as consultas foram cache hits em cache
temporário). Diretórios de execução de teste removidos ao final.

### Problemas ou limitações

- O ramo `exit 10 → parada graciosa` do `full_etl.sh` não é exercitado no teste de 0
  créditos (com tudo em cache nenhuma consulta nova é feita); a lógica de `exit 10`
  da etapa 6 é coberta pelo teste unitário de `--max-new-queries` (seção 2.7 de
  `tests/exemplos_de_testes.md`).
- A etapa 7 depende de `pandas`/`matplotlib`; sem elas, é pulada com aviso (não
  falha a execução).

---

## I. Cobertura real do Shodan na etapa 7 (`comparacao_pipeline`)

### Objetivo

A comparação antiga (`pipeline original 18 col vs estendido 28 col`) era enganosa:
como o CSV de 28 colunas emite uma linha para todo IP (com campos Shodan vazios para
IPs não consultados), quase todos os IPs apareciam como "sem dados", e "ainda não
consultados" ficava ~0. O objetivo foi medir a cobertura real a partir do cache
Shodan, separando três categorias.

### Alterações realizadas

- `src/7_analyze_results.py`:
  - `analisar_comparacao(df, caminho_original, caminho_cache, output_dir)`: usa o
    cache (`logs/shodan_cache.json`, via novo argumento `--cache-file`) como fonte
    de verdade. Categorias: **consultados com dados** (`found=true`), **consultados
    sem dados** (`found=false`) e **não consultados** (ausentes do cache), sempre
    restritos ao universo (`--original-csv`, ou o próprio CSV de entrada).
  - Novo argumento `--cache-file` (padrão `logs/shodan_cache.json`).
  - Nova função `ler_cache_shodan()`; `plot_comparacao()` e o CSV
    `comparacao_pipeline.csv` agora têm três categorias e colunas
    `categoria,ips_unicos,pct_original`.
  - Removida a função `ips_com_metadados_shodan()` e a constante
    `SHODAN_FIELD_COLS` (sem uso após a mudança).

### Comportamento esperado

- `comparacao_pipeline.csv` com três linhas (com dados / sem dados / não consultados)
  e `pct_original` percentual do universo.
- Gráfico `comparacao_pipeline.png` com as três barras.
- Resumo em stderr "Cobertura do enriquecimento Shodan" com os três números e o
  tamanho do universo.

> **Nota (atualizado pela seção L):** o filtro `found=true` passou a ser o padrão
> da etapa 7, a cobertura passou a ter 2 categorias por padrão
> (`--incluir-nao-enriquecidos` restaura as 3) e o `comparacao_pipeline.png` foi
> removido.

### Testes realizados e resultados

| Teste | Resultado esperado | Resultado obtido |
|---|---|---|
| `venv/bin/python -m py_compile src/7_analyze_results.py` | compila | OK |
| E2E offline: cache sintético (3 `found=true`, 2 `found=false`), CSV 28-col com 5 IPs (campos Shodan vazios), `--original-csv` com 6 IPs | CSV com 3/2/1 e `pct_original` 50/33.33/16.67; prova que a fonte é o cache, não o CSV | OK — `Consultados com dados no Shodan,3,50.0` / `Consultados sem dados no Shodan,2,33.33` / `Não consultados,1,16.67` |

Teste sem consumo de créditos. Diretórios em `/tmp/opencode` removidos ao final.

### Problemas ou limitações

- A comparação depende do cache estar preenchido com o campo `found` (registros
  antigos gerados antes dessa convenção não têm `found`; são tratados como
  `found=false`, ou seja, "sem dados").
- `--cache-file` aponta por padrão para o cache global; execuções com cache
  temporário devem passar `--cache-file` explicitamente.

---

## H. Coleta Shodan rotativa entre agregados

### Objetivo

Permitir cobrir os 26 agregados do `datasets/e3_full` mesmo quando cada um é grande
demais para ser esgotado em tempo hábil. Em vez de esgotar uma região por vez, a
coleta processa até N consultas **novas** por região e "pula" para a próxima,
acumulando cobertura de todos os agregados ao longo do tempo, compartilhando o cache
global (cache hits não consomem crédito nem respeitam rate-limit).

### Alterações realizadas

- **`src/6_shodan_enrich.py` — `--max-new-queries N`:** encerra graciosamente após N
  consultas novas (cache hits não contam), persiste o cache e sai com código **10**;
  sem atingir o limite, a entrada termina e sai com código 0. `process_pipeline`
  passou a retornar o motivo do término (`concluido`/`parado`/`limite`).
- **`other/shodan_rotation.sh` (novo):** rotacionador. Para cada agregado, prepara
  uma vez `regions/<região>/output.enriched.csv.gz` (etapas 1+2, reaproveitando se já
  existir) e roda a etapa 6 com `--max-new-queries N` e `--stop-file`, descartando o
  stdout e populando o cache. Regiões esgotadas (exit 0) recebem `.done` e são
  puladas; exit 10 alterna para a próxima. Ao concluir todas, gera
  `output.enriched.csv.gz` e `output.shodan.csv.gz` (28 colunas) numa passada rápida
  (tudo cache hit). Opções: `-d`, `-q`, `-p`, `-r`, `-o` (retomada), `-s`, `-c`,
  `--final`. Loga em `<work-dir>/rotacao.log` e por região em `regions/<região>/shodan.log`.

### Comportamento esperado

- Rotação avança de fato a cada rodada (cache hits não bloqueiam).
- `-o <dir>` retoma uma coleta interrompida (regiões `.done` puladas).
- `--stop-file` encerra ao fim da região corrente, com cache persistido.
- Saída final só é gerada automaticamente quando todas as regiões concluem (ou com
  `--final`).

### Testes realizados e resultados

| Teste | Resultado esperado | Resultado obtido |
|---|---|---|
| `venv/bin/python -m py_compile src/6_shodan_enrich.py` | compila | OK |
| `6_shodan_enrich.py --help` | exibe `--max-new-queries` | OK |
| Teste unitário offline (8 verificações: limite, api_calls, cache, 28 colunas, conclusão, stop, sem cap, retomada avança) | todas passam | OK — 8/8 |
| `bash -n other/shodan_rotation.sh` | sintaxe válida | OK |
| `shodan_rotation.sh --help` | ajuda, exit 0, stderr vazio | OK |
| E2E offline (2 pcaps sintéticos Ethernet+IPv4+UDP, cache temporário pré-povoado, `-q 5`) | 0 API calls; `.done` nas 2 regiões; 18 e 28 colunas; `rotacao.log` não vazio | OK — `API calls: 0`; 5 linhas/28 col; `rotacao.log` com 18 linhas |
| Retomada (`-o` no mesmo diretório) | pula `.done` e regera a saída final | OK |

Testes sem gasto de créditos (todas as consultas foram cache hits em cache
temporário). Diretórios de teste em `/tmp/opencode` removidos ao final.

### Problemas ou limitações

- O ramo "exit 10 → próxima região" do rotacionador não é exercitado no teste de 0
  créditos (com tudo em cache nenhuma região atinge o limite); a lógica de limite é
  coberta pelo teste unitário da etapa 6 e o despacho do rotacionador é um `elif`
  simples.
- Regiões ainda não concluídas são reprocessadas do início a cada rodada (cache hits,
  sem rate-limit); o custo é de I/O, não de créditos.
- `--final` com regiões pendentes pode consumir consultas novas (avisado no log).

---

## G. Sincronização da documentação com os datasets atuais (`e3_raw`/`e3_full`)

### Objetivo

A documentação canônica e os testes ainda referenciavam `datasets/e3` (e o default
`datasets/e1`), diretórios que não existem mais. Os datasets reais são
`datasets/e3_raw` (capturas brutas individuais, elegíveis à etapa 0) e
`datasets/e3_full` (26 agregados por região AWS, não elegíveis à etapa 0). Além
disso, o facilitador passou a exigir `-d/--dataset` (default `""`) e ganhou a opção
`-p/--packet-limit`, ambos ainda não documentados.

### Alterações realizadas

- `AGENTS.md`: seção Datasets reescrita para `e3_raw`/`e3_full`; exemplos de execução
  e nome do artefato (`output.shodan.csv.gz`).
- `README.md`, `contexto/pipeline.md`, `contexto/estrutura.md`,
  `contexto/instrucoes.md`: referências `datasets/e3` → `e3_raw`/`e3_full`.
- `contexto/pipeline.md`: descrição do `full_etl.sh` atualizada (`-d` obrigatório,
  `-p/--packet-limit`, custo de ~1 consulta ≈ 1 s por IP novo).
- `tests/exemplos_de_testes.md`: comandos migrados para `e3_raw`/`e3_full`; correção
  de `output.shodan.gz` → `output.shodan.csv.gz`; nova **seção 7** com E2E pequeno e
  coleta longa em background (`tmux`/`nohup`) com parada via `--stop-file`.
- `other/full_etl.sh`: apenas textos de `usage()`/AVISO (`e1`/`e3` →
  `e3_raw`/`e3_full`, `-d` obrigatório) e escape das crases de `` `touch` `` no
  heredoc do `usage()` (as crases não escapadas eram interpretadas como substituição
  de comando, executando `touch` sem operando e imprimindo
  `touch: missing file operand` no `--help`). **Nenhuma mudança de lógica.**
- `Docker/Dockerfile`: diretórios comentados/criados como `e3_raw`/`e3_full`.
- `src/0_select_representative_subset.py`: docstring atualizada para `e3_raw`.
- `contexto/dataset_e3.md`: `output.shodan.gz` → `output.shodan.csv.gz`.

### Comportamento esperado

- Nenhuma referência operacional a `datasets/e3`/`datasets/e1` nos documentos vivos.
- Documentação reflete `-d` obrigatório e a opção `-p` do `full_etl.sh`.
- Nenhuma alteração de comportamento no código do pipeline.

### Testes realizados e resultados

| Teste | Resultado esperado | Resultado obtido |
|---|---|---|
| `bash -n other/full_etl.sh` | sintaxe válida | OK |
| `venv/bin/python -m py_compile src/0_select_representative_subset.py` | compila | OK |
| `rg` por `datasets/e3`/`datasets/e1`/`output.shodan.gz` nos docs vivos | apenas menção histórica em `dataset_e3.md` | OK — só a nota de datasets removidos |
| `other/full_etl.sh --help` | `-d` obrigatório e `-p` documentados, sem ruído em stderr | OK — exit 0, stderr vazio |
| `other/full_etl.sh` sem `-d` | erro de preflight, exit 1 | OK — `[full_etl] ERRO: Diretório do dataset não encontrado:` |

### Problemas ou limitações

- `other/full_etl.sh` com `DATASET=""` (sem `-d`) falha no preflight com a mensagem
  genérica `Diretório do dataset não encontrado:` — funcional, mas pouco explícita
  para o caso "opção obrigatória ausente".
- `src/1_generate_tshark_csv.sh` (legado, substituído pelo `.py`) não consta em
  `contexto/estrutura.md` e ainda cita `datasets/e1`; fora do escopo desta
  sincronização.

---

## F. Parada graciosa da coleta Shodan + gravação atômica do cache

### Objetivo

Permitir executar a coleta Shodan (etapa 6) de forma desatendida por horas (ex.:
durante a madrugada, em subconjunto representativo do Dataset 3) e encerrá-la
manualmente no dia seguinte **sem** (a) perder pendências de cache — créditos já
gastos — nem (b) deixar `output.shodan.csv.gz` truncado. Motivação: o Ctrl+C atual
do `full_etl.sh` envia SIGTERM para a árvore da etapa 6 (zcat/python/gzip); o python
morre pelo handler default (o `atexit` com `cache.flush()` não roda) e o `gzip` é
morto no meio da gravação, corrompendo o artefato.

### Alterações realizadas

1. **`src/6_shodan_enrich.py` — marcador de parada (`--stop-file ARQ`):** no topo do
   laço de cada linha do `process_pipeline`, se o arquivo `ARQ` existir, o loop
   encerra (`break`), persiste o cache (o `cache.flush()` já existente ao final) e o
   processo sai com código 0, permitindo ao `gzip` da ponta finalizar um `.gz`
   íntegro. Relatório final registra "Encerrado por marcador de parada".
2. **`src/6_shodan_enrich.py` — gravação atômica do cache:** `ShodanCache._save()`
   agora grava em arquivo temporário no mesmo diretório (`tempfile.mkstemp`) e
   substitui o cache com `os.replace`, com `flush`+`fsync` antes do replace e limpeza
   do temporário em caso de falha. Um processo morto durante a gravação não corrompe
   mais o JSON inteiro (antes, o `open(..., "w")` direto podia deixar o cache ilegível
   e o `_load` recomeçava vazio — perda total dos créditos).
3. **`other/full_etl.sh` — opção `-s/--stop-file ARQ`:** repassada à etapa 6 como
   `--stop-file`. Padrão: `<diretório da execução>/stop_shodan`. O marcador é
   removido no início da etapa 6 (`rm -f`) e o script loga o comando exato:
   `touch "<ARQ>"`. Documentação de uso adicionada em `pipeline.md`,
   `exemplos_de_testes.md` e `implementacoes_e_testes.md`.

### Comportamento esperado

- Com o marcador ausente: comportamento inalterado (processa tudo, 28 colunas).
- Marcador criado durante a coleta: encerra a linha corrente, faz flush do cache,
  exit 0, `.gz` válido; via `full_etl.sh`, a execução segue para as etapas seguintes
  e loga "Execução concluída".
- Marcador presente desde o início: nenhuma linha processada, saída limpa.
- Nota: a checagem ocorre no topo do laço; uma linha já lida do stdin quando o
  marcador é criado é descartada (não entra no `.gz`), reaparecendo numa execução
  futura sobre o mesmo CSV enriquecido.

### Testes realizados e resultados

| Teste | Resultado esperado | Resultado obtido |
|---|---|---|
| `bash -n other/full_etl.sh` | sintaxe válida | OK |
| `venv/bin/python -m py_compile src/6_shodan_enrich.py` | compila | OK |
| Módulo S1 — sem marcador, 5 linhas em cache (sem API) | 5 linhas na saída | OK — 5 |
| Módulo S2 — marcador preexistente | 0 linhas, saída limpa | OK — 0 |
| Módulo S3 — marcador criado no meio do fluxo | para em ~2 linhas, exit limpo | OK — 2 |
| Cache atômico — save_every=2 + flush | JSON válido com 3 IPs, sem `.tmp` residual | OK |
| Cache atômico — reload após gravação | lê 3 IPs | OK |
| Cache atômico — falha em diretório inexistente | erro logado, `_pending` preservado | OK — pending=1; após criar o dir e re-flush, persistiu |
| `full_etl.sh` com pcap sintético (`/tmp/opencode/ds_stop`, 1 pacote, src já no cache) + `-s` | exit 0, 28 colunas, marcador aceito, log do `touch` | OK — `output.shodan.csv.gz` 1 linha/28 cols; "Execução concluída"; marcador inexistente ao final |

Testes sem gasto de créditos (todos com cache hits; o smoke E2E do `full_etl.sh`
consultou apenas `api.info()`). Diretórios de execução de teste removidos ao final.

### Problemas ou limitações

- A parada por marcador depende de checagem a cada linha; no pior caso uma linha em
  andamento (~1 consulta/segundo) termina antes do encerramento — atraso desprezível
  para o cenário de coleta noturna.
- Ctrl+C (SIGINT/SIGTERM) cru na etapa 6 continua podendo truncar o `output.shodan`
  e perder pendências de cache até o último `--cache-save-every`; o caminho
  recomendado de interrupção é o marcador `--stop-file`.
- `full_etl.sh` continua enviando SIGTERM à árvore da etapa 6 em caso de Ctrl+C
  (comportamento pré-existente, inalterado nesta tarefa).

---

## E. Análise de resultados pós-Shodan (`src/7_analyze_results.py`)

### Objetivo

Criar o script de análise e visualização dos resultados do pipeline enriquecido
(CSV de 28 colunas) exigido pelo Objetivo Específico 4 do TCC (visualizações
comparativas que demonstram o ganho informacional). Implementação incremental:
primeiro OS, depois organizações/ISPs, portas+CVEs, comparação 18 vs 28 e, por fim,
distribuição geográfica × OS.

### Alterações realizadas

- Criação de `src/7_analyze_results.py` (usa apenas `pandas` + `matplotlib`, sem
  seaborn). Lê o CSV de 28 colunas do stdin e gera, no `--output-dir`:
  - `os_distribution.{csv,png}` — IPs únicos de origem por OS detectado;
  - `org_ranking.{csv,png}` e `isp_ranking.{csv,png}` — rankings de orgs/ISPs;
  - `top_ports.{csv,png}` — portas abertas mais comuns;
  - `port_cves.csv` — CVEs associados às top 10 portas (associação aproximada: o
    Shodan agrega CVEs por host, não por serviço/porta);
  - `comparacao_pipeline.{csv,png}` — comparação original (18 col) vs estendido
    (28 col); opcionalmente recebe o CSV de 18 col da etapa 2 via `--original-csv`
    como universo de IPs (sem ele, a base é o próprio CSV de entrada);
  - `geo_os_cross.csv` — distribuição geográfica (país de origem) cruzada com OS:
    contagem de IPs únicos por país×OS (tentativas de plotagem sobre o mapa-múndi
    `other/The_World_map.png` foram abandonadas por ora — scatter com espalhamento
    de pontos coincidentes não ficou satisfatório).
- Todas as análises contam **IPs únicos de origem** (não pacotes).
- Valores vazios de campos Shodan são agrupados em `Sem registro`.

### Comportamento esperado

- Saída em stderr com tabelas resumo (apenas amostra de porta×CVE e país×OS);
  artefatos CSV/PNG gravados no diretório indicado.
- Requer `pandas` e `matplotlib` no venv.

### Testes realizados e resultados

Execução sobre o subset real (`datasets/e3_subset`, etapa 6 limitada a 300 linhas —
216 IPs únicos de origem):

`zcat datasets/e3_subset/output.shodan.csv.gz | venv/bin/python src/7_analyze_results.py --original-csv datasets/e3_subset/output.enriched.csv.gz --output-dir datasets/e3_subset`

| Análise | Resultado esperado | Resultado obtido |
|---|---|---|
| Linhas/colunas | 28 colunas lidas | OK — 300 linhas, 216 IPs |
| OS | poucos IPs com OS | OK — 214 sem registro, Linux 1, Ubuntu 1 |
| Org/ISP | ranking com "Sem registro" no topo | OK — Google LLC 51 (org), Google LLC 57 (ISP) |
| Portas | top = 123 (NTP) | OK — 123 com 57 IPs; depois 80/443/22 |
| porta×CVE | lista de associações | OK — 510 associações no CSV (terminal mostra 20) |
| Comparação 18 vs 28 | mostrar ganho e não-consultados | OK — original 22.970 IPs; processados 216; ganharam metadados 74; sem dados 142; não consultados 22.754 |
| Geo × OS | heatmap só quando há OS | OK — Indonesia/Ubuntu e Iran/Linux (1 IP cada) |

### Problemas ou limitações

- A associação porta×CVE é aproximada (limitação da API, já documentada).
- Com a etapa 6 limitada a 300 linhas no subset atual, a maioria dos 22.970 IPs de
  origem ainda não foi consultada no Shodan — a comparação 18 vs 28 só terá
  significado pleno após execução completa da etapa 6 sobre o subconjunto
  representativo (pendência da fase "Execução do pipeline em subconjunto
  representativo").
- CSV do pipeline não possui cabeçalho; o script assume a ordem fixa de 28 colunas
  (documentada no docstring/`COL_NAMES`).

---

---

## A. Correções do módulo Shodan (`src/6_shodan_enrich.py`)

### Objetivo

Eliminar seis defeitos identificados na revisão do módulo contra os requisitos
RF01–RF07/RNF01–RNF04 do TCC, sem alterar o contrato stdin/stdout nem os campos CSV
(posições 18–27).

### Alterações realizadas

1. **Retry de rate limit limitado** — antes, a retentativa recursiva não decrementava
   o contador, permitindo recursão infinita se o limite persistisse. Agora retenta até
   `MAX_RETRIES` (3x) com espera fixa de `RATE_LIMIT_WAIT` (60s) e, ao esgotar,
   registra erro e devolve registro vazio.
2. **Cache enxuto** — o campo auxiliar `_raw_services` (banners/certificados/HTTP
   completos) não é mais persistido; `ShodanCache._slim()` o remove antes de gravar.
   Mantém os 10 campos CSV + metadados mínimos (`found`, `_services_count`,
   `_queried_at`, `_miss_reason`).
3. **Gravação do cache em lote** — antes, cada IP novo regravava o cache inteiro
   (O(n²) de I/O). Agora acumula em memória e grava a cada N IPs novos
   (`--cache-save-every`, padrão 500), além de `flush()` ao final do pipeline e via
   `atexit`.
4. **Modo demo sem consulta duplicada** — a normalização da resposta foi extraída para
   `_normalize_host()`; a seção 5 do demo reutiliza o `host` já consultado em vez de
   chamar a API uma segunda vez (economia de 1 crédito por demo).
5. **Timestamp tz-aware** — `datetime.utcnow()` substituído por
   `datetime.now(timezone.utc)` (preparação para Python ≥3.12; ambiente atual 3.11).
6. **Validação IPv4 no modo pipeline** — linhas cujo `ip.src` não é um IPv4 válido
   (regex + faixa de octetos) são ignoradas com log de aviso e contadas em
   `lines_skipped`, evitando consultas de lixo à API.

### Comportamento esperado

- Rate limit persistente: 3 tentativas com pausa de 60s e, ao final, registro vazio
  com motivo no cache — sem travamento.
- Cache em disco sem `_raw_services`; gravações espaçadas conforme
  `--cache-save-every`.
- `--demo <IP>` consome exatamente 1 consulta à API.
- Linhas malformadas no modo pipeline são descartadas com log, sem consultar a API.

### Testes realizados e resultados

| Teste | Resultado esperado | Resultado obtido |
|---|---|---|
| `venv/bin/python -m py_compile src/6_shodan_enrich.py` | compila sem erros | OK |
| Suíte local de regressão (29 verificações via `importlib`: `_is_ipv4`, `_normalize_host`, slim/batch/flush do cache, retry limitado com `time.sleep` simulado, pipeline sintético) | todas passam | OK — 29/29 |
| `src/6_shodan_enrich.py --info` contra a API real | autentica e exibe plano/créditos | OK — plano dev, 100 créditos |
| Pipeline sintético com 1 IP real (`printf ... \| ... --cache-file /tmp/opencode/test_cache.json`) | 28 colunas na saída; 2ª execução vira cache hit | OK — 28 colunas; 2ª execução sem chamada à API |
| Cache em disco após execução real | sem `_raw_services`; 10 campos + metadados | OK |

Consumo total de créditos nos testes: 1.

### Problemas ou limitações

- O bug do tshark citado em B motivou o teste end-to-end; nenhum problema pendente
  neste módulo.
- Registros antigos de cache que ainda contenham `_raw_services` são limpos apenas
  quando regravados (a carga em memória os aceita).

---

## B. Workaround tshark para `.pcap.gz` (`src/1_generate_tshark_csv.py`)

### Objetivo

Fazer a etapa de extração funcionar no ambiente atual (tshark 4.6.7), que falha ao
abrir capturas gzip diretamente.

### Problema observado

Ao executar `tshark -r arquivo.pcap.gz`, todas as iterações retornavam
`tshark: You don't have permission to read the file`, embora:

- o arquivo fosse `-rw-r--r--` do próprio usuário (`thr`), com diretórios acessíveis;
- `zcat` lesse o mesmo arquivo normalmente;
- `zcat arquivo.pcap.gz \| tshark -r -` extraísse os pacotes corretamente.

Diagnóstico: mensagem enganosa do tshark 4.6.7 na abertura de gzip — não é problema
de permissões do sistema de arquivos.

### Alterações realizadas

Linha de extração alterada para descomprimir e ler do stdin:
`zcat "$f" | tshark -r - ... | gzip -c >> "${OUTPUT}"` (com quoting de `"$f"`).

### Comportamento esperado

`src/1_generate_tshark_csv.py datasets/eX_subset` produz `output.csv.gz` com as 7
colunas originais, sem erros de leitura.

### Teste realizado e resultados

| Item | Resultado esperado | Resultado obtido |
|---|---|---|
| `zcat ... \| tshark -r -` isolado | extrai campos | OK |
| `src/1_generate_tshark_csv.py datasets/e3_subset` (subconjunto existente) | `output.csv.gz` com dados

### Problemas ou limitações

- Se o Wireshark for atualizado para uma versão que volte a abrir `.pcap.gz`
  diretamente, o `zcat` pode ser removido (nota registrada também em
  `tests/exemplos_de_testes.md` §1.2).

---

## C. `KeyError: 'region'` no enriquecimento (`src/2_enrich_csv.py`)

### Objetivo

Corrigir a falha `KeyError: 'region'` (linha 127) que interrompia a etapa 2.

### Causa raiz

A região AWS só era definida dentro do ramo `else` do `try` de GeoIP. Quando
`solver.city(ipdst)` falhava (IP de destino fora da base GeoIP2-City — ex.: destinos
privados `172.31.x.x` presentes nas capturas), o registro entrava no cache **sem**
a chave `region`, e o acesso posterior `cachedst[ipdst]['region']` interrompia o
processo.

### Alterações realizadas

O bloco de consulta da região AWS foi movido para fora do `else` do GeoIP: agora é
executado sempre que o destino é novo no cache, com fallback `"Unknown"` em caso de
exceção. A região AWS é independente do sucesso do GeoIP.

### Comportamento esperado

- Destinos fora da base GeoIP recebem fallback `ZZ`/`ZZ Country`/região `Unknown`,
  sem erro.
- Saída com 18 colunas; reconciliação
  `linhas de entrada = enriquecidas + anomalous_entries + trimmed_entries`.

### Teste realizado e resultados

Comando: `zcat datasets/e3_subset/output.csv.gz | python src/2_enrich_csv.py | gzip > datasets/e3_subset/output_enriched.csv.gz`

| Métrica | Resultado esperado | Resultado obtido |
|---|---|---|
| Código de saída | 0, sem traceback | OK — exit=0 |
| Linhas enriquecidas | entrada − anômalas − aparadas | OK — 318.364 (= 318.591 − 227 − 0) |
| Colunas por linha | 18 | OK |
| Destino privado `172.31.39.30` | fallback ZZ/Unknown | OK — visível na 1ª linha |
| Região AWS preenchida p/ destinos AWS | região válida | Parcial — no e3_subset muitos destinos são privados ⇒ `Unknown` (comportamento correto do fallback) |
| `logs/cacheinfo.txt` | estatísticas coerentes | OK — 26 destinos distintos, 318.338 hits |

### Decisão registrada: linhas anômalas

As 227 linhas rejeitadas pelo "DIRTY IP CHECK" (2_enrich_csv.py:41) são pacotes
multi-camada IP (ICMP de erro que embute o cabeçalho original / túneis IP-in-IP):
`tshark` emite `ip.src`/`ip.dst` duplicados com vírgula escapada (`\,`) e o split
ingênuo gera ≠7 campos. **Decisão: manter o descarte como está** (~0,07% dos dados),
preservando o comportamento original do pipeline. Não tratar esses pacotes.

### Problemas ou limitações

- No subconjunto testado (e3), a maioria dos destinos são endereços privados ⇒
  `Unknown` na região AWS (comportamento correto do fallback). Para validar regiões
  AWS não triviais, usar um subconjunto com mais destinos públicos.

---

## D. Facilitador `other/full_etl.sh` atualizado ao pipeline atual

### Objetivo

O script antigo apenas imprimia um encadeamento obsoleto (etapas 1–3, sem Shodan,
sem diretório de execução próprio). O objetivo foi transformá-lo em um executor real
do pipeline atual (etapas 0–6) com opções de limitação e de consumidores opcionais.

### Alterações realizadas

- Reescrita completa de `other/full_etl.sh` (`set -euo pipefail`, `trap ERR`,
  execução a partir do `PROJECT_ROOT`, independente do CWD).
- Cada execução cria um **novo diretório** `datasets/execucao_pipeline_<origem>_<data_hora>`
  (sufixo `_2`, `_3`... em colisão de timestamp). O dataset de origem só é lido, via
  links simbólicos; nada de execuções anteriores é removido ou alterado.
- Opções:
  - `-d/--dataset DIR` — origem das capturas (padrão `datasets/e3`);
  - `-n/--num-pcaps N` — usa a etapa 0 para selecionar até N capturas; se a etapa 0
    não encontrar nomenclatura elegível (ex.: agregados do `datasets/e3`), faz
    fallback vinculando as N primeiras `.pcap.gz` por ordem alfabética;
  - `-q/--shodan-queries N` — alimenta a etapa 6 só com as N primeiras linhas do CSV
    enriquecido (via `awk 'NR<=n'`, que consome toda a entrada e evita SIGPIPE);
  - `--with-neo4j` — gera `output_neo4j.cypher`; exige os arquivos
    `enriched_unique_{source,destination}_IPs.csv` na raiz do projeto;
  - `--with-mysql` — importa no banco; exige `mysql.connector` no interpretador usado.
- Saídas sempre geradas: `output.csv.gz` (etapa 1), `output.enriched.csv.gz`
  (etapa 2), `output.tex` (etapa 3) e `output.shodan.gz` (etapa 6).
- Preflight antes de qualquer processamento: existência do dataset, validade dos
  argumentos, `tshark` no PATH, dependências Python (`geoip2`, `awsipranges`,
  `shodan`, `dotenv`), presença de `SHODAN_API_KEY` em `.env` (verificação silenciosa,
  sem expor o valor) e pré-requisitos de Neo4j/MySQL quando solicitados.
- Após a etapa 2, contagem em passada única (`awk` sobre o CSV enriquecido) das
  linhas com destino no fallback (coluna M = `ZZ`): quando **100%** dos destinos
  caem no fallback, emite `[full_etl] AVISO:` com a causa típica (destinos privados,
  ex.: destinos privados) e a sugestão de processar destinos públicos.

### Comportamento esperado

- Execuções sucessivas criam diretórios isolados; o dataset de origem permanece
  intocado; falhas abortam com mensagem `[full_etl] ERRO:` e exit 1, sem criar
  diretório quando ocorrem no preflight.
- CSV enriquecido com 18 colunas; saída Shodan com 28 colunas.

### Testes realizados e resultados

| # | Cenário | Resultado esperado | Resultado obtido |
|---|---|---|---|
| 1 | `bash -n other/full_etl.sh` | sintaxe válida | OK |
| 2 | `--help` | texto de ajuda, exit 0 | OK |
| 3 | opção desconhecida / dataset inexistente / `-n abc` / `-n 0` / `-q -3` | exit 1, nenhum diretório criado | OK |
| 4 | `--with-neo4j` sem fixtures na raiz | abort antecipado, nada criado | OK |
| 5 | `--with-mysql` sem `mysql.connector` no venv | abort antecipado | OK |
| 6 | Execução completa com 2 pcaps sintéticos mínimos (`/tmp/opencode/ds_fake`, nomes inelegíveis), `-q 3` | exit 0; 4 artefatos gerados; 18 e 28 colunas | OK — Shodan processou 2 linhas (2 API calls, IPs novos; cache 234→236) |
| 7 | Fallback: mesmo dataset sintético com `-n 1` | aviso + 1 captura por ordem alfabética | OK |
| 8 | `--with-neo4j` com fixtures temporários de IPs únicos | `output_neo4j.cypher` com `create`/`merge` | OK — fixtures removidos após o teste |
| 9 | Execução real: `-d datasets/e3 -n 4 -q 5` | exit 0; artefatos + manifestos da etapa 0 | OK — etapa 0 selecionou 26 capturas (≥1 por região); Shodan: 5 linhas, 5 cache hits, 0 API calls |
| 10 | Execução a partir de outro CWD (`/tmp/opencode`) | artefatos no `datasets/` do projeto | OK |
| 11 | Aviso de fallback: pcaps sintéticos só com dst privado (`ds_priv`) | `[full_etl] AVISO:` de 100% em fallback | OK — "100% dos destinos ficaram no fallback GeoIP/AWS (1 linhas...)" |
| 12 | Aviso de fallback: pcaps sintéticos mistos, dst privado + público (`ds_mix`) | nenhum AVISO emitido | OK — 0 ocorrências |

Os diretórios de execução criados nos testes foram removidos ao final.

### Problemas ou limitações

- `-n` menor que o número de regiões do dataset resulta em 1 captura por região
  (26 no `datasets/e3`): comportamento de `allocate_quotas` na etapa 0
  (`min_per_region=1`), documentado na ajuda do script. Não alterado por ser
  decisão de estratificação metodológica.
- No `datasets/e3` atual, muitas linhas têm destino privado, de modo que as colunas
  M–R (país/cidade/lat/long/região AWS de destino) podem cair no fallback
  `ZZ`/`-9999`/`Unknown` — comportamento projetado da etapa 2, agora sinalizado pelo
  aviso do facilitador. Análises por origem (colunas H–L) seguem válidas.
- A etapa 4 lê 17 colunas do CSV enriquecido (índices deslocados em relação às 18
  colunas atuais) e depende dos `enriched_unique_*_IPs.csv`, hoje não gerados
  (bloco comentado em `src/2_enrich_csv.py`). Limitação pré-existente, fora do
  escopo desta alteração; o facilitador apenas valida os pré-requisitos e registra.
- `mysql.connector` não está instalado no venv local; com servidor indisponível a
  própria etapa 5 imprime `FAILED connecting to MySQL` e a execução segue.
- Sem `-q`, todos os IPs de origem novos consomem ~1 consulta Shodan cada; o aviso
  aparece no log da etapa 6.
