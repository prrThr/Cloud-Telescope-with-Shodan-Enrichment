# Datasets e1 × e3 — estrutura, motivo da diferença e uso nos testes

Este documento registra por que `datasets/e1` e `datasets/e3` têm organizações
distintas e como isso afeta a execução do pipeline (em especial a etapa 0,
`src/0_select_representative_subset.py`).

---

## 1. Estrutura real de cada dataset

### `datasets/e1` — coleta bruta (capturas individuais)

```
datasets/e1/
├── af-south-1b-13.244.71.194-20230501-0017.pcap.gz   ┐
├── af-south-1b-13.244.71.194-20230501-0017.pcap.txt  ├ milhares de pares
├── af-south-1b-13.244.71.194-20230501-1217.pcap.gz   │ (captura + metadados)
├── ...                                               ┘
└── aggregated/
    ├── af-south-1.pcap.gz      ┐
    ├── ap-east-1.pcap.gz       │ 26 consolidados
    └── us-west-2.pcap.gz       ┘ (um por região)
```

- **2.311 capturas `.pcap.gz`** elegíveis (≈4.600 arquivos contando os `.pcap.txt`),
  cobrindo **26 regiões AWS**, janela de ~maio/2023.
- Cada arquivo segue a nomenclatura bruta completa:
  `<região><az>-<IP>-<YYYYMMDD>-<HHMM>.pcap.gz` (ex.: `af-south-1b-13.244.71.194-20230501-0017.pcap.gz`).
- `aggregated/` contém os 26 consolidados por região (`af-south-1.pcap.gz`, ...),
  produzidos localmente por `other/aggregate_pcaps.sh`.

### `datasets/e3` — dataset-alvo já consolidado (por região)

```
datasets/e3/
├── e3_af-south-1.pcap.gz        ┐
├── e3_ap-east-1.pcap.gz         │ 26 consolidados
├── ...                          │ (um por região AWS)
├── e3_us-west-2.pcap.gz         ┘
├── aggregate.log.gz             # log da agregação
├── capinfos/                    # metadados das capturas
└── final_results/               # saídas de processamento anterior (~17 GiB)
```

- **26 arquivos `e3_<região>.pcap.gz`**, um por região AWS — a série completa de
  out/2023 a fev/2024 (~531 milhões de eventos) já concatenada por região.
- Os nomes **não** carregam AZ/IP/timestamp: o timestamp individual se perdeu na
  agregação (é recuperável apenas via `capinfos/`).

---

## 2. Por que são diferentes?

São a **mesma natureza de dado em níveis de consolidação diferentes**:

| Aspecto | e1 | e3 |
|---|---|---|
| Granularidade | captura horária individual (`região+AZ+IP+timestamp`) | série completa consolidada por região |
| Período | ~maio/2023 | out/2023 – fev/2024 |
| Papel no projeto | coleta bruta preservada; base para testes com amostra pequena | dataset-alvo do TCC, entregue já processado/agregado |
| Análogo interno | `e1/aggregated/*.pcap.gz` (gerado por `aggregate_pcaps.sh`) | a própria raiz do `e3` |

O **e3 veio agregado**: ele é o *produto* do mesmo fluxo que gera `e1/aggregated` —
as capturas brutas originais do e3 não fazem parte da entrega. Já o **e1 exige**
(potencialmente) o pipeline completo porque preserva a coleta bruta; seu diretório
`aggregated/` é opcional para o fluxo principal e espelha o formato do e3.

---

## 3. Por que a etapa 0 falha com `datasets/e3`

`src/0_select_representative_subset.py` estratifica por região e faz seleção
sistemática **temporal** a partir do nome do arquivo (`FILENAME_RE`, linha 54), que
exige `<região>[-_]<IP>[-_]<data>[-_]<hora>`.

- Nos nomes `e3_<região>.pcap.gz` não há IP/data/hora ⇒ **0 arquivos elegíveis** ⇒
  `"Nenhum arquivo de captura compatível foi encontrado."`.
- Conceitualmente também não haveria o que amostrar: cada arquivo do e3 **já é** a
  série completa de uma região (não há múltiplos timestamps por região para
  espaçar a amostra).

Evidência empírica (via `list_candidate_files`, somente leitura de nomes):

```
elegíveis em datasets/e1: 2311   (26 regiões)
elegíveis em datasets/e3: 0
```

---

## 4. Como prosseguir com os testes

### Testes de desenvolvimento (amostra pequena) — usar o e1

```sh
python src/0_select_representative_subset.py datasets/e1 \
    --output datasets/e1_subset --max-files 15 --clean

src/1_generate_tshark_csv.sh datasets/e1_subset
zcat datasets/e1_subset/output.csv.gz \
    | python src/2_enrich_csv.py | gzip > datasets/e1_subset/output_enriched.csv.gz
zcat datasets/e1_subset/output_enriched.csv.gz \
    | python src/6_shodan_enrich.py | gzip > datasets/e1_subset/output.shodan.gz
zcat datasets/e1_subset/output_enriched.csv.gz \
    | python src/3_summarize_radiation.py > datasets/e1_subset/output.tex
```

### Execução de produção (dataset completo do TCC) — usar o e3 sem a etapa 0

Consumir cada agregado diretamente na etapa 1, um por vez (26 regiões):

```sh
for f in datasets/e3/e3_*.pcap.gz; do
    zcat "$f" | tshark -r - -M 100000 -t ad -T fields -e _ws.col.Time -e ip.src \
        -e ip.dst -e tcp.dstport -e tcp.flags.str -e udp.dstport -e icmp.type \
        -Eseparator=, --log-level critical | gzip >> "saida/${f:t}.csv.gz"
done
```

(O padrão acima é o mesmo de `other/full_etl.sh` / `other/process_regions.sh`,
que podem ser usados como facilitadores.)

### Regras de convívio com os dados

- `datasets/e3/final_results/` é **saída** de processamento anterior: nunca usar como
  entrada nem escanear (ver `AGENTS.md`).
- `datasets/e1/aggregated/` só deve ser lido com necessidade explícita.
- A etapa 0 continua válida e necessária para qualquer conjunto **bruto** (padrão
  completo de nomenclatura) — hoje, a raiz do `datasets/e1`.
