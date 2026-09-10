# Exemplos de Testes — ibr-etl

Guia prático para validar a **situação atual** do pipeline. Este documento é um
**living spec**: deve ser **atualizado sempre que o pipeline ou seus modos de uso
mudarem** durante o desenvolvimento (novas etapas, novos argumentos, mudanças de
formato). Se um exemplo aqui ficar desatualizado, corrija-o no lugar de ignorá-lo.

> **IMPORTANTE — créditos Shodan**
> A conta Shodan é de plano acadêmico com créditos limitados. Os modos `--info`
> (gratuito) e os testes em cache não consomem créditos; `--demo` e consultas a
> IPs novos no modo pipeline consomem 1 crédito cada. Sempre que possível, reutilize
> o cache (`logs/shodan_cache.json`) ou um `--cache-file` temporário.

---

## 0. Pré-requisitos

- Python 3.11 (venv): `venv/bin/python` — contém a biblioteca `shodan`.
- Chave de API em `.env` (`SHODAN_API_KEY=...`). Nunca exponha/comite o valor.
- **Nunca** liste, leia ou abra arquivos dentro de `datasets/` (ver `AGENTS.md`).

Verificação rápida de sintaxe dos módulos alterados recentemente:

```sh
venv/bin/python -m py_compile src/2_enrich_csv.py src/6_shodan_enrich.py
```

---

## 1. Pipeline principal (stdin → stdout, compactado com gzip)

Contrato: cada etapa lê CSV do **stdin** e emite CSV no **stdout**. Os comandos
abaixos usam um diretório de amostra pequeno e **removem `output*.csv*` antigos**
antes, conforme as regras do projeto.

### 1.1 Etapa 0 — Amostragem (seleção de subconjunto)

A etapa 0 reconhece a nomenclatura bruta (`<região><az>-<IP>-<data>-<hora>`) e
funciona com o `datasets/e3` atual (capturas brutas com nomenclatura padrão).

```sh
rm -rf datasets/e3_subset
python3 src/0_select_representative_subset.py datasets/e3 \
    --output datasets/e3_subset --max-files 12 --clean
```

> Gera `subset_manifest.{csv,json}` dentro do diretório de saída. Use `--max-files`
> pequeno para testes. **Cuidado:** o comando grava dentro de `datasets/` — não leia
> o conteúdo gerado, apenas valide que o comando terminou sem erro.

### 1.2 Etapa 1 — Extração (tshark)

```sh
python3 src/1_generate_tshark_csv.py datasets/e3_subset
```

> Produz `datasets/e3_subset/output.csv.gz` com colunas
> `time,ip.src,ip.dst,tcp.dstport,tcp.flags.str,udp.dstport,icmp.type`.
>
> **Nota:** o script descomprime cada captura com `zcat` e lê via stdin
> (`tshark -r -`). Motivo: o tshark 4.6.7 falha ao abrir `.pcap.gz` diretamente com
> o erro enganoso `You don't have permission to read the file` (as permissões do
> arquivo estão corretas; o problema é a abertura do gzip pelo tshark). Se trocar a
> versão do Wireshark e `-r arquivo.pcap.gz` voltar a funcionar, o `zcat` pode ser
> removido.
>
> Verificação: `zcat datasets/e3_subset/output.csv.gz | wc -l` deve ser > 0.

### 1.3 Etapa 2 — Enriquecimento (GeoIP + AWS)

```sh
zcat datasets/e3_subset/output.csv.gz \
    | venv/bin/python src/2_enrich_csv.py \
    | gzip > datasets/e3_subset/output.enriched.csv.gz
```

> Adiciona GeoIP de origem/destino + região AWS (18 colunas por linha). Gera logs
> auxiliares em `logs/` (`cacheinfo.txt`, `anomalous_entries.csv`,
> `trimmed_entries.csv`).
>
> **Comportamentos esperados:**
> - IP fora da base GeoIP (ex.: destino privado `172.31.x.x`) recebe fallback
>   `ZZ`/`ZZ Country`/região `Unknown` — não gera erro.
> - **Reconciliação de linhas:** `entrada = enriquecidas + anomalous_entries +
>   trimmed_entries`. As anômalas são pacotes multi-camada IP (ICMP de erro que
>   embute o cabeçalho original / túneis IP-in-IP), nos quais `ip.src`/`ip.dst`
>   aparecem duplicados (`\,` no dump do tshark) e falham no "DIRTY IP CHECK"
>   (2_enrich_csv.py:41). Esse descarte é **intencional** (decisão de projeto);
>   não "corrigir".
>
> Verificação rápida:
> ```sh
> zcat datasets/e3_subset/output.enriched.csv.gz | head -1 | awk -F, '{print NF}'  # 18
> ```

### 1.4 Etapa 3 — Resumo (LaTeX)

```sh
zcat datasets/e3_subset/output.enriched.csv.gz \
    | venv/bin/python src/3_summarize_radiation.py > datasets/e3_subset/output.tex
```

> Agregações de radiação; saída em texto/LaTeX (não gzip).

### 1.5 Etapa 6 — Enriquecimento Shodan

```sh
zcat datasets/e3_subset/output.enriched.csv.gz \
    | venv/bin/python src/6_shodan_enrich.py \
    | gzip > datasets/e3_subset/output.shodan.csv.gz
```

> Adiciona os 10 campos Shodan (posições 18–27). Usa o cache padrão
> `logs/shodan_cache.json` e rate-limit de 1 s.

**Contagem de colunas:** a linha de saída deve ter **28 campos** (18 originais +
10 Shodan). Conferir com:

```sh
zcat datasets/e3_subset/output.shodan.gz | head -1 | awk -F, '{print NF}'
```

---

## 2. Etapa 6 Shodan — modos isolados

### 2.1 `--info` (gratuito — não consome créditos)

```sh
venv/bin/python src/6_shodan_enrich.py --info
```

> Deve exibir plano, créditos de consulta/scan e confirma a autenticação (RF03).

### 2.2 `--demo <IP>` (1 crédito por IP)

```sh
venv/bin/python src/6_shodan_enrich.py --demo 8.8.8.8
venv/bin/python src/6_shodan_enrich.py --demo 8.8.8.8 --json
```

> Exibe a resposta estruturada e a seção "Campos Adicionados ao CSV". O IP
> consultado é o mesmo em todas as seções (não há consulta duplicada).

### 2.3 Pipeline Shodan com entrada sintética (teste de formato)

Teste rápido com uma linha mínima de 18 campos. **Atenção:** um IP que não está no
cache consome 1 crédito; use um `--cache-file` temporário para não poluir o cache real.

```sh
printf '2023-05-01 00:00:00,8.8.8.8,f,f,f,f,f,f,f,f,f,f,f,f,f,f,f,f\n' \
    | venv/bin/python src/6_shodan_enrich.py \
        --cache-file /tmp/opencode/test_cache.json --rate-limit 0
```

- **1ª execução:** consulta a API (1 crédito) e popula o cache.
- **2ª execução (mesmo IP):** cache hit — **0 créditos**; confere RF02/RF06.

### 2.4 Validação de linhas malformadas (sem custo)

IPs inválidos ou linhas com menos de 18 campos são ignoradas e contadas em
`lines_skipped`. Exemplo (nenhum crédito consumido, pois nenhum IP válido é
consultado se já estiver no cache):

```sh
printf '2023-05-01 00:00:00,999.999.1.1,f,f,f,f,f,f,f,f,f,f,f,f,f,f,f,f\ncurta\n' \
    | venv/bin/python src/6_shodan_enrich.py --cache-file /tmp/opencode/test_cache.json --rate-limit 0
```

> Deve logar `Linha ignorada — IPv4 de origem inválido` e
> `Linha ignorada — esperado ≥18 campos`.

### 2.5 Cache — enxuto e gravação em lote

O cache em disco **não** guarda banners/CPEs completos (`_raw_services`). Conferir
que o arquivo está enxuto:

```sh
venv/bin/python -c "import json; d=json.load(open('logs/shodan_cache.json')); k=list(d)[0]; print(sorted(d[k].keys())); print('_raw_services presente:', '_raw_services' in d[k])"
```

A gravação ocorre a cada N IPs novos (`--cache-save-every`, padrão 500) e no
encerramento (`flush`), de forma **atômica** (arquivo temporário + `os.replace` —
um processo morto no meio de uma gravação não corrompe o cache existente). Para
forçar gravação mais frequente em teste:

```sh
... | venv/bin/python src/6_shodan_enrich.py --cache-save-every 10
```

### 2.6 Interrupção graciosa de coleta longa (`--stop-file`)

Para executar a coleta Shodan de madrugada (ex.: `full_etl.sh`) e encerrá-la na
manhã seguinte **sem perder pendências de cache e com `.gz` íntegro**, use o
marcador de parada: enquanto o arquivo não existir a coleta prossegue; quando é
criado (`touch`), o módulo termina a linha corrente, persiste o cache (`flush`) e
sai com código 0. Testar (sem gastar créditos — IPs já no cache):

```sh
venv/bin/python -c "
import importlib.util
spec = importlib.util.spec_from_file_location('m6','src/6_shodan_enrich.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
"
```

> **Nota:** a checagem ocorre no topo do laço de cada linha — se o marcador for
> criado enquanto uma linha já foi lida do stdin, essa linha é descartada (não
> entra no `output.shodan`); o cache e o `.gz` permanecem íntegros e a linha
> reaparece numa execução futura sobre o mesmo CSV enriquecido.

---

## 3. Etapas 4 e 5 — consumidores paralelos (grafo / MySQL)

As etapas 4 e 5 consomem o mesmo CSV enriquecido **em paralelo** ao resumo.

- **Etapa 4 (grafo Neo4j):** lê `enriched_unique_source_IPs.csv` /
  `enriched_unique_destination_IPs.csv` gerados pela etapa 2 e emite Cypher no stdout.
- **Etapa 5 (MySQL):** importa o CSV enriquecido; requer servidor MySQL e credenciais
  configuradas no script (`host`, `user`, `password`).

Como dependem de arquivos intermediários e de serviços externos (Neo4j/MySQL), para
testes rápidos do pipeline priorize as etapas 0–3 e 6.

---

## 4. Etapa 7 — Análise de resultados

Lê o CSV de 28 colunas (enriquecido + Shodan) e gera distribuições estatísticas
contando IPs únicos de origem: distribuição por OS, ranking de organizações,
ranking de ISPs, portas abertas mais comuns com CVEs associados, comparação
pipeline original (18 col) vs estendido (28 col) e distribuição geográfica de
origem cruzada com OS.

```sh
zcat datasets/e3_subset/output.shodan.csv.gz \
    | venv/bin/python src/7_analyze_results.py \
        --original-csv datasets/e3_subset/output.enriched.csv.gz \
        --output-dir datasets/e3_subset
```

> Requer `pandas` e `matplotlib` no venv. Gera, para cada análise, um CSV e/ou PNG:
> `os_distribution`, `org_ranking`, `isp_ranking`, `top_ports` + `port_cves` (CSV
> completo; o terminal exibe apenas amostra), `comparacao_pipeline` e `geo_os_cross`.
> Colunas: `shodan_os`/`shodan_org`/`shodan_isp`/`porta` + `ips_unicos,percentual`;
> `port_cves`: `porta,cve,ips_afetados`; `comparacao_pipeline`:
> `categoria,ips_unicos,pct_original,pct_processados`;
> `geo_os_cross`: `src_country,shodan_os,ips_unicos`.
> A comparação usa `--original-csv` (CSV de 18 col da etapa 2) como universo de IPs;
> sem ele, a base é o próprio CSV de entrada. A análise geográfica gera apenas a
> tabela `geo_os_cross.csv` (país de origem × OS, contagem de IPs únicos); a
> plotagem em mapa (`geo_os_map.png`) foi descontinuada por ora.

**Verificações:**
- exit 0;
- `os_distribution.csv`, `org_ranking.csv`, `isp_ranking.csv`, `top_ports.csv`,
  `comparacao_pipeline.csv` e `geo_os_cross.csv` presentes;
- PNGs correspondentes presentes e não vazios;
- `port_cves.csv` presente (com cabeçalho mesmo sem associações);
- `comparacao_pipeline.csv` com colunas
  `categoria,ips_unicos,pct_original,pct_processados`; quando executado sobre o
  subset truncado (300 linhas), deve indicar `Ainda não consultados` > 0;
- `geo_os_cross.csv` presente (colunas `src_country,shodan_os,ips_unicos`).


---

## 5. Verificação geral (amostra pequena)

Valide qualquer mudança com uma **amostra pequena** e removendo saídas antigas antes:

```sh
rm -rf datasets/e3_subset
python3 src/0_select_representative_subset.py datasets/e3 --output datasets/e3_subset --max-files 12 --clean
python3 src/1_generate_tshark_csv.py datasets/e3_subset
zcat datasets/e3_subset/output.csv.gz | venv/bin/python src/2_enrich_csv.py | gzip > datasets/e3_subset/output.enriched.csv.gz
zcat datasets/e3_subset/output.enriched.csv.gz | venv/bin/python src/3_summarize_radiation.py > datasets/e3_subset/output.tex
zcat datasets/e3_subset/output.enriched.csv.gz | awk 'NR<=300' | venv/bin/python src/6_shodan_enrich.py | gzip > datasets/e3_subset/output.shodan.csv.gz
zcat datasets/e3_subset/output.shodan.csv.gz | venv/bin/python src/7_analyze_results.py --output-dir datasets/e3_subset
```

> Não há framework de lint/test padronizado no projeto. `py_compile` + execução com
> amostra pequena + conferência do número de colunas são as validações de referência.

---

## 6. Facilitador `other/full_etl.sh`

Executa o pipeline por inteiro (etapas 1→2→3→6; etapa 0 quando `-n`; etapas 4 e 5
opcionais) criando um **novo diretório** `datasets/execucao_pipeline_<origem>_<data_hora>`
por execução. O dataset de origem só é lido (links simbólicos); execuções anteriores
nunca são removidas ou alteradas. Pré-requisitos (tshark, dependências Python,
`SHODAN_API_KEY` no `.env`, fixtures de Neo4j/MySQL quando solicitados) são validados
**antes** de qualquer processamento.

```sh
other/full_etl.sh --help                          # ajuda
other/full_etl.sh                                 # tudo do datasets/e3 (padrão)
other/full_etl.sh -d datasets/e3 -n 12            # etapa 0 com até 12 capturas
other/full_etl.sh -d datasets/e3 -n 12 -q 60      # ... e Shodan limitado a 60 linhas (~60 consultas no pior caso)
```

> **Nota sobre `-n`:** a estratificação da etapa 0 garante ao menos 1 captura por
> região presente no dataset (26 regiões no `datasets/e3`); `-n` menor que o número
> de regiões resulta em 1 captura por região (o script registra a quantidade real
> em "Capturas na execução").
>
> **Créditos Shodan:** sem `-q`, todos os IPs de origem novos consomem ~1 consulta
> cada. Com `-q N`, apenas as N primeiras linhas do CSV enriquecido chegam à etapa 6.

**Coleta longa (ex.: madrugada) com parada manual no dia seguinte:** a etapa 6
respeita um marcador de parada (`-s/--stop-file`; padrão `<execução>/stop_shodan`).
Ao criar o arquivo, o módulo encerra a linha corrente, faz `flush` do cache e sai
com código 0 — a execução segue e o `output.shodan.csv.gz` fica íntegro:

```sh
other/full_etl.sh -d datasets/e3 -n 300 &        # inicia a coleta
# na manhã seguinte, encerrar graciosamente (o caminho exato é logado pelo script):
touch datasets/execucao_pipeline_<origem>_<data_hora>/stop_shodan
```

### Teste rápido sem tocar nos datasets reais

Capturas sintéticas mínimas (nomes inelegíveis para a etapa 0, exercitando o modo
"todas as capturas" e o fallback alfabético):

```sh
mkdir -p /tmp/opencode/ds_fake
# ... gerar *.pcap.gz mínimos em /tmp/opencode/ds_fake ...
other/full_etl.sh -d /tmp/opencode/ds_fake -q 3
```

Verificações:

- exit 0 e diretório `datasets/execucao_pipeline_ds_fake_*` criado;
- artefatos presentes: `output.csv.gz`, `output.enriched.csv.gz`,
  `output.tex`, `output.shodan.gz`;
- `zcat <execução>/output.enriched.csv.gz | head -1 | awk -F, '{print NF}'` → 18;
- `zcat <execução>/output.shodan.csv.gz | head -1 | awk -F, '{print NF}'` → 28.

### Aviso de fallback de destino

Após a etapa 2, o script conta as linhas com destino no fallback (coluna M = `ZZ`)
e, **se 100% delas** caírem no fallback, emite um `[full_etl] AVISO:` explicando a
causa típica (destinos privados) e sugerindo destinos públicos. Execuções com ao menos
um destino geolocalizado não emitem o aviso. Para testar os dois caminhos sem tocar
nos datasets reais:

```sh
mkdir -p /tmp/opencode/ds_priv /tmp/opencode/ds_mix
# ... gerar pcaps sintéticos mínimos:
#     ds_priv/a1.pcap.gz → 1 pacote com dst privado (ex.: 172.31.39.30)
#     ds_mix/b1.pcap.gz  → 1 pacote dst privado + 1 pacote dst público AWS
other/full_etl.sh -d /tmp/opencode/ds_priv   # deve exibir o AVISO
other/full_etl.sh -d /tmp/opencode/ds_mix    # NÃO deve exibir o AVISO
```

### Opicionais

- `--with-neo4j`: exige `enriched_unique_source_IPs.csv` +
  `enriched_unique_destination_IPs.csv` na raiz do projeto (bloco correspondente da
  etapa 2 descomentado); gera `output_neo4j.cypher`. Sem os arquivos, aborta antes
  de iniciar.
- `--with-mysql`: exige `mysql.connector` no interpretador usado (`venv/bin/python`
  se existir) e servidor/credenciais em `src/5_import_mysql.py`. Sem servidor ativo,
  a própria etapa 5 imprime `FAILED connecting to MySQL` e a execução segue.

### Caminhos de erro (sem efeitos colaterais)

Opção desconhecida, dataset inexistente, `-n`/`-q` não positivos, pré-requisitos
ausentes → mensagem `[full_etl] ERRO:` e exit 1 **sem criar** diretório de execução.
