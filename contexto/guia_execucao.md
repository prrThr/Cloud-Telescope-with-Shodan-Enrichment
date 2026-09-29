# Guia de execução do pipeline (`ibr-etl`)

Guia prático de operação: como rodar o ETL completo, como rodar etapa por etapa,
como parar graciosamente, como deixar a coleta Shodan em background e onde ficam
as consultas, e como gerar as visualizações/comparações.

> Referências canônicas: `contexto/pipeline.md` (etapas), `tests/exemplos_de_testes.md`
> (comandos de teste) e `AGENTS.md` (regras operacionais). Em caso de divergência,
> prevalecem o código e o `AGENTS.md`.
>
> **Datasets:** nunca liste, leia ou escaneie `datasets/` (ver `AGENTS.md`). Use
> sempre `-n`/`--max-files` pequenos em testes de desenvolvimento.

---

## 0. Pré-requisitos

- `tshark` no `PATH`.
- Python 3.11 com o venv (`venv/bin/python`) e os pacotes:
  `geoip2`, `awsipranges`, `shodan`, `python-dotenv` (e `pandas`, `matplotlib`
  para a etapa 7).
- `.env` com `SHODAN_API_KEY=<configurada no ambiente>` (nunca exponha o valor).
- `GeoIP2-City.mmdb` na raiz do projeto.

Verificação rápida da chave e dos créditos (gratuito, não consome crédito):

```sh
venv/bin/python src/6_shodan_enrich.py --info
```

---

## 1. Executar o pipeline completo (ETL)

O comando canônico é o facilitador `other/full_etl.sh`. Ele roda as etapas 0→7
(a etapa 0 quando `-n`; 4 e 5 opcionais), cria um **novo diretório** por execução
(`datasets/execucao_pipeline_<origem>_<data_hora>`) e nunca altera execuções
anteriores. O dataset de origem é apenas lido (links simbólicos).

```sh
other/full_etl.sh --help                                  # ajuda completa
other/full_etl.sh -d datasets/e3_full                     # tudo do e3_full (26 capturas)
other/full_etl.sh -d datasets/e3_raw -n 12               # etapa 0 com até 12 capturas
other/full_etl.sh -d datasets/e3_raw -n 12 -q 60         # ... e Shodan limitado a 60 consultas novas
other/full_etl.sh -d datasets/e3_full -n 1 -p 60 -q 60   # 1 captura, 60 pacotes, até 60 consultas novas
```

Opções principais:

| Opção | Efeito |
|---|---|
| `-d, --dataset DIR` | **Obrigatório**. Diretório de origem (`datasets/e3_raw` ou `datasets/e3_full`) |
| `-n, --num-pcaps N` | Usa a etapa 0 para selecionar até N capturas (padrão: todas) |
| `-p, --packet-limit N` | Limite de pacotes por captura na etapa 1 (tshark `-c`) |
| `-q, --shodan-queries N` | Limita a etapa 6 a até N consultas **novas** (cache hits não contam) |
| `-s, --stop-file ARQ` | Marcador de parada da etapa 6 (padrão `<execução>/stop_shodan`) |
| `-c, --cache-file ARQ` | Cache Shodan usado nas etapas 6 e 7 (padrão `logs/shodan_cache.json`) |
| `--rate-limit N` | Delay entre requisições Shodan, em segundos (padrão 1.0) |
| `--cache-save-every N` | Grava o cache a cada N IPs novos (padrão 500) |
| `--region REGIÃO` | Região AWS de fallback na etapa 2 |
| `--with-neo4j` | Gera `output_neo4j.cypher` (requer os `enriched_unique_*_IPs.csv` na raiz) |
| `--with-mysql` | Importa para MySQL/MariaDB (requer servidor e credenciais) |

Artefatos gerados no diretório da execução:

```text
output.csv.gz            etapa 1 — extração tshark
output.enriched.csv.gz   etapa 2 — enriquecimento GeoIP + AWS (18 colunas)
output.tex               etapa 3 — resumo LaTeX
output.shodan.csv.gz     etapa 6 — enriquecimento Shodan (28 colunas)
*.csv / *.png            etapa 7 — análise de resultados
output_neo4j.cypher      etapa 4 (opcional)
```

> A etapa 7 roda sempre que `pandas`/`matplotlib` estiverem disponíveis; caso
> contrário, é pulada com aviso. As etapas 4 e 5 só rodam com `--with-neo4j` /
> `--with-mysql`.

---

## 2. Executar o pipeline completo, etapa por etapa (manual)

O contrato do pipeline é **stdin → stdout com CSV**; o encadeamento é feito por
pipes. Todas as etapas resolvem caminhos relativos ao `PROJECT_ROOT`, então
podem ser executadas de qualquer diretório. Exemplo com `datasets/e3_subset`:

```sh
# 0. Amostragem (apenas para capturas brutas — datasets/e3_raw)
python3 src/0_select_representative_subset.py datasets/e3_raw \
    --output datasets/e3_subset --max-files 12 --clean

# 1. Extração (tshark) → output.csv.gz
python3 src/1_generate_tshark_csv.py datasets/e3_subset

# 2. Enriquecimento GeoIP + AWS → output.enriched.csv.gz (18 colunas)
zcat datasets/e3_subset/output.csv.gz \
    | venv/bin/python src/2_enrich_csv.py \
    | gzip > datasets/e3_subset/output.enriched.csv.gz

# 3. Resumo LaTeX → output.tex
zcat datasets/e3_subset/output.enriched.csv.gz \
    | venv/bin/python src/3_summarize_radiation.py > datasets/e3_subset/output.tex

# 6. Enriquecimento Shodan → output.shodan.csv.gz (28 colunas)
zcat datasets/e3_subset/output.enriched.csv.gz \
    | venv/bin/python src/6_shodan_enrich.py \
    | gzip > datasets/e3_subset/output.shodan.csv.gz

# 7. Análise de resultados (tabelas + gráficos)
zcat datasets/e3_subset/output.shodan.csv.gz \
    | venv/bin/python src/7_analyze_results.py \
        --original-csv datasets/e3_subset/output.enriched.csv.gz \
        --cache-file logs/shodan_cache.json \
        --output-dir datasets/e3_subset
```

Etapas 4 (grafo Neo4j) e 5 (MySQL), quando desejadas:

```sh
# 4. Grafo Neo4j → Cypher (requer enriched_unique_{source,destination}_IPs.csv na raiz)
zcat datasets/e3_subset/output.enriched.csv.gz \
    | venv/bin/python src/4_generate_graph.py > datasets/e3_subset/output_neo4j.cypher

# 5. Importação MySQL/MariaDB
zcat datasets/e3_subset/output.enriched.csv.gz \
    | venv/bin/python src/5_import_mysql.py
```

Verificação de formato (contagem de colunas):

```sh
zcat datasets/e3_subset/output.enriched.csv.gz | head -1 | awk -F, '{print NF}'   # 18
zcat datasets/e3_subset/output.shodan.csv.gz   | head -1 | awk -F, '{print NF}'   # 28
```

---

## 3. Parar graciosamente a execução

### 3.1 `full_etl.sh` — Ctrl+C

- **1º Ctrl+C:** interrompe a etapa corrente de forma graciosa, mantém os dados
  parciais e segue para a próxima etapa (etapas dependentes de entrada ausente
  são puladas).
- **2º Ctrl+C:** encerra imediatamente (código 130), preservando os artefatos
  parciais no diretório da execução.

> Para a **etapa 6 (Shodan)**, prefira o marcador de parada (abaixo): o Ctrl+C
> pode deixar a linha corrente fora do `.gz` e não é o método recomendado.

### 3.2 Etapa 6 (Shodan) — marcador de parada (`--stop-file`)

Enquanto o arquivo marcador **não existir**, a coleta prossegue; ao criá-lo com
`touch`, o módulo encerra na fronteira entre linhas, persiste o cache (`flush`) e
sai com **código 0**, com o `output.shodan.csv.gz` íntegro.

No `full_etl.sh`, o caminho padrão é `<execução>/stop_shodan` e o script loga o
comando `touch` exato:

```sh
# inicia a coleta
other/full_etl.sh -d datasets/e3_full &

# encerra graciosamente (use o caminho logado pela execução)
touch datasets/execucao_pipeline_<origem>_<data_hora>/stop_shodan
```

Uso direto no módulo (pipeline manual):

```sh
... | venv/bin/python src/6_shodan_enrich.py --stop-file /tmp/parar
# em outra sessão, quando quiser parar:
touch /tmp/parar
```

> O marcador é removido automaticamente no início da etapa 6 (`rm -f`), então
> crie-o **depois** de a coleta começar.
>
> **Nota:** a checagem ocorre no topo do laço de cada linha — a linha já lida
> quando o marcador aparece é descartada (não entra no `.gz`) e reaparece numa
> execução futura sobre o mesmo CSV enriquecido.

---

## 4. Coleta Shodan em background (e como parar) + onde ficam as consultas

### 4.1 Rodar em background com `tmux`

O rate-limit do Shodan é ~1 consulta/s; coletas de milhares de IPs levam horas.
Rode em uma sessão `tmux` para poder fechar o terminal.

```sh
# 1. cria (ou reusa) a sessão
tmux new -s ibr-shodan

# 2. dentro da sessão, inicia a coleta
cd ~/Faculdade/TCC/ibr-etl
other/full_etl.sh -d datasets/e3_full 2>&1 | tee -a logs/coleta_shodan_$(date +%Y%m%d).log

# 3. destaca da sessão: Ctrl+b, depois d  (o processo continua)
```

Acompanhar / retomar e parar:

```sh
tmux ls                          # lista sessões
tmux attach -t ibr-shodan        # reanexa
tail -f logs/shodan_enrich.log   # progresso da etapa 6

# encerrar graciosamente (caminho logado por "[full_etl] Marcador de parada")
touch datasets/execucao_pipeline_e3_full_<data_hora>/stop_shodan
```

Alternativa sem `tmux` (desacopla do terminal via `nohup`):

```sh
nohup other/full_etl.sh -d datasets/e3_full > logs/coleta_shodan.log 2>&1 &
# encerre depois com --stop-file apontando para um caminho conhecido
```

### 4.2 Coleta rotativa entre regiões (background)

Quando um agregado é grande demais para ser esgotado, use o rotacionador, que
alterna entre as 26 regiões (`-q` consultas novas por região/rodada):

```sh
tmux new -s ibr-rotacao
cd ~/Faculdade/TCC/ibr-etl
other/shodan_rotation.sh -d datasets/e3_full -q 1000 2>&1 | tee -a logs/rotacao_shodan_$(date +%Y%m%d).log
# Ctrl+b, d para destacar

# encerrar graciosamente (caminho logado em "[rotacao] Marcador de parada")
touch datasets/rotacao_shodan_e3_full_<data_hora>/stop_shodan
```

Retomar uma coleta existente: repita o comando com `-o <work-dir>`. Regiões
esgotadas (`.done`) são puladas; ao concluir (ou com `--final`), o script gera
`output.enriched.csv.gz` e `output.shodan.csv.gz` (28 colunas).

### 4.3 Onde ficam armazenadas as consultas do Shodan

| O quê | Onde |
|---|---|
| Cache por IP (fonte de verdade das consultas — evita gastar crédito) | `logs/shodan_cache.json` (ou o caminho de `--cache-file` / `-c`) |
| Log da etapa 6 (progresso, API calls, erros) | `logs/shodan_enrich.log` |
| Cache/log da rotação | `<work-dir>/rotacao.log` e `<work-dir>/regions/<região>/shodan.log` |
| Regiões já concluídas na rotação | `<work-dir>/regions/<região>/.done` |
| Marcador de parada em uso | `<execução>/stop_shodan` (ou `--stop-file`) |

Formato do cache (JSON por IP, sem banners/serviços brutos):

```json
{
  "1.2.3.4": { "found": true, "org": "...", "open_ports": [22, 80], "cves": ["CVE-..."], ... },
  "5.6.7.8": { "found": false, "org": "", "open_ports": [], ... }
}
```

- `found=true` ⇒ IP consultado **com** dados; `found=false` ⇒ consultado **sem**
  dados; IP **ausente** ⇒ ainda **não consultado**.
- Gravação em lote a cada `--cache-save-every` IPs novos (padrão 500) e no
  encerramento, de forma **atômica** (temporário + `os.replace`), então um
  processo morto no meio não corrompe o cache existente.
- Para não poluir o cache real em testes, use `--cache-file` temporário
  (ex.: `/tmp/opencode/test_cache.json`).

Inspectar quantos IPs já estão no cache (sem consumir crédito):

```sh
venv/bin/python -c "import json; print('IPs em cache:', len(json.load(open('logs/shodan_cache.json'))))"
```

---

## 5. Gerar as visualizações e comparações

As visualizações e comparações são produzidas pela **etapa 7**
(`src/7_analyze_results.py`), que lê o CSV de 28 colunas e gera, por análise, um
CSV e/ou um PNG.

### 5.1 Via pipeline completo

A etapa 7 roda automaticamente no `full_etl.sh` (quando `pandas`/`matplotlib`
estão disponíveis), gravando tudo no diretório da execução:

```sh
other/full_etl.sh -d datasets/e3_full -n 1 -p 60 -q 10
```

### 5.2 Manual

```sh
zcat datasets/e3_subset/output.shodan.csv.gz \
    | venv/bin/python src/7_analyze_results.py \
        --original-csv datasets/e3_subset/output.enriched.csv.gz \
        --cache-file logs/shodan_cache.json \
        --output-dir datasets/e3_subset
```

- `--output-dir` (padrão `.`): diretório dos CSV/PNG.
- `--original-csv`: CSV de 18 colunas (etapa 2) usado como **universo** de IPs de
  origem na comparação de cobertura. Sem ele, a base é o próprio CSV de entrada.
- `--cache-file`: cache Shodan (padrão `logs/shodan_cache.json`), fonte de verdade
  da cobertura.

### 5.3 Artefatos gerados

| Arquivo | Conteúdo |
|---|---|
| `os_distribution.csv` / `.png` | Distribuição de dispositivos por OS detectado |
| `org_ranking.csv` / `.png` | Ranking de organizações por IPs únicos de origem |
| `isp_ranking.csv` / `.png` | Ranking de ISPs por IPs únicos de origem |
| `top_ports.csv` / `.png` | Portas abertas mais comuns |
| `port_cves.csv` | CVEs associados às portas mais comuns (associação aproximada) |
| `comparacao_pipeline.csv` / `.png` | Cobertura do enriquecimento Shodan (comparação) |
| `geo_os_cross.csv` | Distribuição geográfica de origem (país) × OS detectado |

> `geo_os_map.png` foi descontinuado; a análise geográfica gera apenas
> `geo_os_cross.csv`. As colunas de contagem são `ips_unicos` e `percentual`.

### 5.4 Comparação de cobertura (`comparacao_pipeline`)

Separa os IPs únicos de origem do universo (`--original-csv`) em três categorias,
medidas a partir do cache:

- **Consultados com dados no Shodan** — no cache com `found=true`;
- **Consultados sem dados no Shodan** — no cache com `found=false`;
- **Não consultados** — ausentes do cache.

Saída em `comparacao_pipeline.csv` (`categoria,ips_unicos,pct_original`) e
`comparacao_pipeline.png`.

---

## 6. Referência rápida

```sh
# pipeline completo
other/full_etl.sh -d datasets/e3_full -q 60

# etapa isolada (contrato stdin → stdout)
zcat output.enriched.csv.gz | venv/bin/python src/6_shodan_enrich.py | gzip > output.shodan.csv.gz

# parada graciosa do Shodan
touch datasets/execucao_pipeline_<origem>_<data_hora>/stop_shodan

# background
tmux new -s ibr-shodan   # Ctrl+b, d para destacar

# visualizações/comparações
zcat output.shodan.csv.gz | venv/bin/python src/7_analyze_results.py \
    --original-csv output.enriched.csv.gz --output-dir .
```

Documentos relacionados: `contexto/pipeline.md`, `tests/exemplos_de_testes.md`,
`contexto/dataset_e3.md`, `contexto/implementacoes_e_testes.md`.
