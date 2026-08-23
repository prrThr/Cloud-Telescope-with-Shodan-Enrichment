# Registro de implementações e testes — correções pós-banca

Registro das implementações realizadas nas etapas 1, 2 e 6 do pipeline, seguindo o
formato exigido por `contexto/instrucoes.md` (seção 7), com distinção explícita entre
resultado esperado e resultado obtido (seção 10).

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

## B. Workaround tshark para `.pcap.gz` (`src/1_generate_tshark_csv.sh`)

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

`src/1_generate_tshark_csv.sh datasets/eX_subset` produz `output.csv.gz` com as 7
colunas originais, sem erros de leitura.

### Teste realizado e resultados

| Item | Resultado esperado | Resultado obtido |
|---|---|---|
| `zcat ... \| tshark -r -` isolado | extrai campos | OK |
| `src/1_generate_tshark_csv.sh datasets/e1_subset` (subconjunto existente) | `output.csv.gz` com dados | OK — 318.591 linhas |

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

Comando: `zcat datasets/e1_subset/output.csv.gz | python src/2_enrich_csv.py | gzip > datasets/e1_subset/output_enriched.csv.gz`

| Métrica | Resultado esperado | Resultado obtido |
|---|---|---|
| Código de saída | 0, sem traceback | OK — exit=0 |
| Linhas enriquecidas | entrada − anômalas − aparadas | OK — 318.364 (= 318.591 − 227 − 0) |
| Colunas por linha | 18 | OK |
| Destino privado `172.31.39.30` | fallback ZZ/Unknown | OK — visível na 1ª linha |
| Região AWS preenchida p/ destinos AWS | região válida | Parcial — no e1_subset todos os destinos são privados ⇒ `Unknown` (comportamento correto do fallback) |
| `logs/cacheinfo.txt` | estatísticas coerentes | OK — 26 destinos distintos, 318.338 hits |

### Decisão registrada: linhas anômalas

As 227 linhas rejeitadas pelo "DIRTY IP CHECK" (2_enrich_csv.py:41) são pacotes
multi-camada IP (ICMP de erro que embute o cabeçalho original / túneis IP-in-IP):
`tshark` emite `ip.src`/`ip.dst` duplicados com vírgula escapada (`\,`) e o split
ingênuo gera ≠7 campos. **Decisão: manter o descarte como está** (~0,07% dos dados),
preservando o comportamento original do pipeline. Não tratar esses pacotes.

### Problemas ou limitações

- No subconjunto testado, nenhuma região AWS concreta aparece na coluna 17 (todos os
  destinos capturados são endereços privados das instâncias). Para validar regiões
  AWS não triviais, usar um subconjunto com destinos públicos (ex.: `datasets/e3`).

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
  - `-d/--dataset DIR` — origem das capturas (padrão `datasets/e1`);
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
| 9 | Execução real: `-d datasets/e1 -n 4 -q 5` | exit 0; artefatos + manifestos da etapa 0 | OK — etapa 0 selecionou 26 capturas (≥1 por região); Shodan: 5 linhas, 5 cache hits, 0 API calls |
| 10 | Execução a partir de outro CWD (`/tmp/opencode`) | artefatos no `datasets/` do projeto | OK |

Os diretórios de execução criados nos testes foram removidos ao final.

### Problemas ou limitações

- `-n` menor que o número de regiões do dataset resulta em 1 captura por região
  (26 no `datasets/e1`): comportamento de `allocate_quotas` na etapa 0
  (`min_per_region=1`), documentado na ajuda do script. Não alterado por ser
  decisão de estratificação metodológica.
- A etapa 4 lê 17 colunas do CSV enriquecido (índices deslocados em relação às 18
  colunas atuais) e depende dos `enriched_unique_*_IPs.csv`, hoje não gerados
  (bloco comentado em `src/2_enrich_csv.py`). Limitação pré-existente, fora do
  escopo desta alteração; o facilitador apenas valida os pré-requisitos e registra.
- `mysql.connector` não está instalado no venv local; com servidor indisponível a
  própria etapa 5 imprime `FAILED connecting to MySQL` e a execução segue.
- Sem `-q`, todos os IPs de origem novos consomem ~1 consulta Shodan cada; o aviso
  aparece no log da etapa 6.
