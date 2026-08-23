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
abaixo usam um diretório de amostra pequeno e **removem `output*.csv*` antigos**
antes, conforme as regras do projeto.

### 1.1 Etapa 0 — Amostragem (seleção de subconjunto)

A etapa 0 exige a nomenclatura bruta (`<região><az>-<IP>-<data>-<hora>`), presente na
raiz de `datasets/e1`. Os agregados do `datasets/e3` (`e3_<região>.pcap.gz`) **não**
são elegíveis — detalhes em `contexto/e1_vs_e3.md`.

```sh
rm -rf datasets/e1_subset
python3 src/0_select_representative_subset.py datasets/e1 \
    --output datasets/e1_subset --max-files 12 --clean
```

> Gera `subset_manifest.{csv,json}` dentro do diretório de saída. Use `--max-files`
> pequeno para testes. **Cuidado:** o comando grava dentro de `datasets/` — não leia
> o conteúdo gerado, apenas valide que o comando terminou sem erro.

### 1.2 Etapa 1 — Extração (tshark)

```sh
src/1_generate_tshark_csv.sh datasets/e1_subset
```

> Produz `datasets/e1_subset/output.csv.gz` com colunas
> `time,ip.src,ip.dst,tcp.dstport,tcp.flags.str,udp.dstport,icmp.type`.
>
> **Nota:** o script descomprime cada captura com `zcat` e lê via stdin
> (`tshark -r -`). Motivo: o tshark 4.6.7 falha ao abrir `.pcap.gz` diretamente com
> o erro enganoso `You don't have permission to read the file` (as permissões do
> arquivo estão corretas; o problema é a abertura do gzip pelo tshark). Se trocar a
> versão do Wireshark e `-r arquivo.pcap.gz` voltar a funcionar, o `zcat` pode ser
> removido.
>
> Verificação: `zcat datasets/e1_subset/output.csv.gz | wc -l` deve ser > 0.

### 1.3 Etapa 2 — Enriquecimento (GeoIP + AWS)

```sh
zcat datasets/e1_subset/output.csv.gz \
    | venv/bin/python src/2_enrich_csv.py \
    | gzip > datasets/e1_subset/output.enriched.csv.gz
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
>   (2_enrich_csv.py:41). Esse descarte é **intencional** (decisão de projeto,
>   ~0,07% no e1_subset); não "corrigir".
>
> Verificação rápida:
> ```sh
> zcat datasets/e1_subset/output.enriched.csv.gz | head -1 | awk -F, '{print NF}'  # 18
> ```

### 1.4 Etapa 3 — Resumo (LaTeX)

```sh
zcat datasets/e1_subset/output.enriched.csv.gz \
    | venv/bin/python src/3_summarize_radiation.py > datasets/e1_subset/output.tex
```

> Agregações de radiação; saída em texto/LaTeX (não gzip).

### 1.5 Etapa 6 — Enriquecimento Shodan

```sh
zcat datasets/e1_subset/output.enriched.csv.gz \
    | venv/bin/python src/6_shodan_enrich.py \
    | gzip > datasets/e1_subset/output.shodan.gz
```

> Adiciona os 10 campos Shodan (posições 18–27). Usa o cache padrão
> `logs/shodan_cache.json` e rate-limit de 1 s.

**Contagem de colunas:** a linha de saída deve ter **28 campos** (18 originais +
10 Shodan). Conferir com:

```sh
zcat datasets/e1_subset/output.shodan.gz | head -1 | awk -F, '{print NF}'
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
encerramento (`flush`). Para forçar gravação mais frequente em teste:

```sh
... | venv/bin/python src/6_shodan_enrich.py --cache-save-every 10
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

## 4. Verificação geral (amostra pequena)

Valide qualquer mudança com uma **amostra pequena** e removendo saídas antigas antes:

```sh
rm -rf datasets/e1_subset
python3 src/0_select_representative_subset.py datasets/e3 --output datasets/e1_subset --max-files 12 --clean
src/1_generate_tshark_csv.sh datasets/e1_subset
zcat datasets/e1_subset/output.csv.gz | venv/bin/python src/2_enrich_csv.py | gzip > datasets/e1_subset/output.enriched.csv.gz
zcat datasets/e1_subset/output.enriched.csv.gz | venv/bin/python src/3_summarize_radiation.py > datasets/e1_subset/output.tex
zcat datasets/e1_subset/output.enriched.csv.gz | venv/bin/python src/6_shodan_enrich.py | gzip > datasets/e1_subset/output.shodan.gz
```

> Não há framework de lint/test padronizado no projeto. `py_compile` + execução com
> amostra pequena + conferência do número de colunas são as validações de referência.
