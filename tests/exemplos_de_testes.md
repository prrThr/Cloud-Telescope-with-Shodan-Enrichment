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
funciona com o `datasets/e3_raw` (capturas brutas com nomenclatura padrão). Não se
aplica ao `datasets/e3_full` (agregado por região).

```sh
rm -rf datasets/e3_subset
python3 src/0_select_representative_subset.py datasets/e3_raw \
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
zcat datasets/e3_subset/output.shodan.csv.gz | head -1 | awk -F, '{print NF}'
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

### 2.7 Limite de consultas novas (`--max-new-queries`, base da rotação)

Encerra após N consultas **novas** (cache hits não contam) e sai com **código 10**;
sai com código 0 quando a entrada termina. Como cache hits não dormem no
rate-limit, uma segunda passada avança para os próximos IPs novos. Verificação
offline (0 créditos) com `query_shodan` simulado:

```sh
venv/bin/python - <<'PY'
import io, sys, tempfile, importlib.util
spec = importlib.util.spec_from_file_location('m6', 'src/6_shodan_enrich.py')
m6 = importlib.util.module_from_spec(spec); spec.loader.exec_module(m6)
m6.time.sleep = lambda s: None
calls = {'n': 0}
def fake(api, ip, retries=m6.MAX_RETRIES):
    calls['n'] += 1
    return {"found": True, "org":"x","isp":"y","asn":"AS1","os":"","open_ports":[],
            "cpes":[],"cves":[],"tags":[],"hostnames":[],"last_seen":"",
            "_services_count":0,"_raw_services":[],"_queried_at":"t"}
m6.query_shodan = fake
linhas = "".join(f"2023-01-01 00:00:00,10.0.0.{i},f,f,f,f,f,f,f,f,f,f,f,f,f,f,f,f\n"
                 for i in range(1, 6))
cache = m6.ShodanCache(tempfile.mktemp(suffix='.json'), save_every=100)
old_in, old_out = sys.stdin, sys.stdout
sys.stdin, sys.stdout = io.StringIO(linhas), io.StringIO()
status = m6.process_pipeline(None, cache, rate_limit=0, max_new_queries=3)
sys.stdin, sys.stdout = old_in, old_out
print('status:', status, '| api_calls:', calls['n'])   # status: limite | api_calls: 3
assert status == 'limite' and calls['n'] == 3
PY
```

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
python3 src/0_select_representative_subset.py datasets/e3_raw --output datasets/e3_subset --max-files 12 --clean
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

> **`-d/--dataset` é obrigatório** (sem padrão). Use `datasets/e3_raw` (capturas
> brutas individuais, elegíveis à etapa 0) ou `datasets/e3_full` (agregado por região,
> vinculado por ordem alfabética).

```sh
other/full_etl.sh --help                              # ajuda
other/full_etl.sh -d datasets/e3_full                 # tudo do e3_full (26 capturas)
other/full_etl.sh -d datasets/e3_raw -n 12            # etapa 0 com até 12 capturas
other/full_etl.sh -d datasets/e3_raw -n 12 -q 60      # ... e Shodan limitado a 60 linhas (~60 consultas no pior caso)
other/full_etl.sh -d datasets/e3_full -n 1 -p 60 -q 60  # 1 captura, 60 pacotes, 60 linhas no Shodan
```

> **Nota sobre `-n`:** a estratificação da etapa 0 garante ao menos 1 captura por
> região presente no dataset (26 regiões no `datasets/e3_raw`); `-n` menor que o
> número de regiões resulta em 1 captura por região (o script registra a quantidade
> real em "Capturas na execução"). Em `datasets/e3_full` a etapa 0 não se aplica: os
> 26 agregados são vinculados por ordem alfabética.
>
> **`-p/--packet-limit N`** limita pacotes por captura na etapa 1 (tshark `-c`),
> acelerando bastante a extração em testes.
>
> **Créditos Shodan:** cada IP de origem **novo** consome ~1 consulta (~1 s de
> rate-limit). Sem `-q`, todos os IPs novos do CSV enriquecido são consultados; com
> `-q N`, apenas as N primeiras linhas chegam à etapa 6. IPs já no cache
> (`logs/shodan_cache.json`) não consomem créditos.

**Coleta longa (ex.: madrugada) com parada manual no dia seguinte:** a etapa 6
respeita um marcador de parada (`-s/--stop-file`; padrão `<execução>/stop_shodan`).
Ao criar o arquivo, o módulo encerra a linha corrente, faz `flush` do cache e sai
com código 0 — a execução segue e o `output.shodan.csv.gz` fica íntegro:

```sh
other/full_etl.sh -d datasets/e3_full &          # inicia a coleta
# na manhã seguinte, encerrar graciosamente (o caminho exato é logado pelo script):
touch datasets/execucao_pipeline_<origem>_<data_hora>/stop_shodan
```

> Para manter a coleta viva mesmo ao fechar o terminal, rode dentro de uma sessão
> `tmux` (ver seção 7).

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
  `output.tex`, `output.shodan.csv.gz`;
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

---

## 7. E2E pequeno e coleta longa em background

### 7.1 E2E pequeno (recomendado para validar uma alteração)

Usa o `e3_full` (destinos públicos ⇒ GeoIP significativo) com **1 captura**, limite
de 60 pacotes na extração e no máximo 10 consultas Shodan. Lembrete: cada IP de
origem **novo** custa ~1 consulta (~1 s); IPs já em cache não custam crédito.

```sh
other/full_etl.sh -d datasets/e3_full -n 1 -p 60 -q 10
```

Verificações (copie o caminho `datasets/execucao_pipeline_<origem>_<data_hora>` logado
ao final da execução para `RUN`; **não liste `datasets/`** — ver `AGENTS.md`):

```sh
RUN=datasets/execucao_pipeline_e3_full_<data_hora>   # caminho logado pelo full_etl.sh
zcat "$RUN/output.enriched.csv.gz" | head -1 | awk -F, '{print NF}'   # 18
zcat "$RUN/output.shodan.csv.gz"   | head -1 | awk -F, '{print NF}'   # 28
zcat "$RUN/output.shodan.csv.gz"   | wc -l                            # <= 10
```

Alternativa usando a amostragem estratificada do `e3_raw` (26 capturas, uma por
região, e no máximo 5 consultas Shodan):

```sh
other/full_etl.sh -d datasets/e3_raw -n 12 -q 5
```

> `-q` deve ser inteiro positivo. Para um E2E **sem consumir créditos**, restrinja a
> etapa 6 a IPs já presentes em `logs/shodan_cache.json` (cache hits) ou valide-a
> isoladamente com o cache existente (seção 2.3). As etapas 0–3 não usam a API do
> Shodan e podem ser testadas à vontade.

### 7.2 Coleta longa em background com `tmux`

O rate-limit do Shodan é de ~1 consulta/s. Uma coleta com alguns milhares de IPs
novos leva de dezenas de minutos a horas — rode em uma sessão `tmux` separada para
poder fechar o terminal e continuar trabalhando em outra etapa.

```sh
# 1. cria (ou reusa) uma sessão dedicada
tmux new -s ibr-shodan

# 2. dentro da sessão, inicia a coleta em um diretório novo.
#    -d obrigatório; sem -q a etapa 6 consulta todos os IPs de origem novos.
cd ~/Faculdade/TCC/ibr-etl
other/full_etl.sh -d datasets/e3_full 2>&1 | tee -a logs/coleta_shodan_$(date +%Y%m%d).log

# 3. destaca da sessão: Ctrl+b, depois d  (o processo continua rodando)
```

Acompanhar / retomar:

```sh
tmux ls                       # lista sessões
tmux attach -t ibr-shodan     # reanexa
tail -f logs/shodan_enrich.log   # progresso da etapa 6 (a cada 1000 linhas)
```

Encerrar a coleta graciosamente (sem perder cache nem truncar o `.gz`) — o caminho
exato do marcador é logado por `[full_etl] Marcador de parada da etapa 6`:

```sh
touch datasets/execucao_pipeline_e3_full_<data_hora>/stop_shodan
```

> Alternativa sem `tmux` (mesmo efeito de desacoplar do terminal): `nohup other/full_etl.sh -d datasets/e3_full > logs/coleta_shodan.log 2>&1 &`.
> Nesse caso, use `--stop-file` com caminho conhecido para encerrar depois, e
> `tail -f logs/shodan_enrich.log` para acompanhar. Prefira `tmux` por permitir
> reanexar e ver o progresso interativo.

---

## 8. Coleta rotativa entre agregados (`other/shodan_rotation.sh`)

Quando um único agregado é grande demais para ser esgotado em tempo hábil, o
rotacionador alterna entre as 26 regiões: processa até N consultas **novas** por
região e passa para a próxima, avançando a cada rodada (cache hits são pulados sem
rate-limit). Regiões esgotadas viram `.done` e são ignoradas; ao final, gera o CSV
de 28 colunas numa passada rápida.

Uso típico (coleta longa, em `tmux`):

```sh
tmux new -s ibr-rotacao
cd ~/Faculdade/TCC/ibr-etl
other/shodan_rotation.sh -d datasets/e3_full -q 1000 2>&1 | tee -a logs/rotacao_shodan_$(date +%Y%m%d).log
# Ctrl+b, d para destacar
```

- `-q 1000`: até 1000 consultas **novas** por região por rodada.
- `-o <dir>`: reaproveita um diretório existente para **retomar**.
- `-c <cache>`: cache compartilhado (padrão do módulo: `logs/shodan_cache.json`).
- `-p <N>`: limita pacotes por captura na extração (útil em teste).
- `-r <R>`: número máximo de rodadas (padrão: até concluir tudo ou `--stop-file`).
- `-s <arq>`: marcador de parada (padrão `<work-dir>/stop_shodan`).

Encerrar graciosamente (o caminho é logado em `[rotacao] Marcador de parada`):

```sh
touch datasets/rotacao_shodan_e3_full_<data_hora>/stop_shodan
```

### 8.1 Teste offline (0 créditos) com pcaps sintéticos

Pré-povoe um cache temporário com os IPs de origem das capturas para que a etapa 6
não faça nenhuma consulta à API. Gere pcaps mínimos (Ethernet+IPv4+UDP) e rode o
rotacionador:

```sh
mkdir -p /tmp/opencode/rot_ds
# ... gerar e3_reg-a.pcap.gz e e3_reg-b.pcap.gz com IPs de origem distintos ...
# ... criar /tmp/opencode/rot_cache.json com esses IPs de origem já "found" ...
other/shodan_rotation.sh -d /tmp/opencode/rot_ds -q 5 \
    -c /tmp/opencode/rot_cache.json -o /tmp/opencode/rot_work
```

Verificações:

- exit 0; `[rotacao] Todas as regiões concluídas.`;
- `regions/<região>/.done` presente para cada região;
- `rotacao.log` não vazio;
- `zcat <work>/output.enriched.csv.gz | head -1 | awk -F, '{print NF}'` → 18;
- `zcat <work>/output.shodan.csv.gz | head -1 | awk -F, '{print NF}'` → 28;
- nenhuma chamada de API (`API calls: 0` no `logs/shodan_enrich.log`).

> **Retomada:** rode de novo com o mesmo `-o <dir>` — regiões `.done` são puladas e
> a saída final é regerada.
>
> **Caminho de limite (`--max-new-queries` → exit 10):** validado pela verificação
> offline da seção 2.7; com IPs já no cache nenhuma região atinge o limite, então o
> ramo de "pular para a próxima região" não é exercitado no teste de 0 créditos.
