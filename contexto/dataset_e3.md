# Dataset e3 — estrutura e uso no pipeline

Este documento descreve a estrutura atual do dataset e como utilizá-lo no pipeline.

---

## 1. Estrutura do dataset

### `datasets/e3` — capturas brutas (atual)

O dataset e3 contém capturas brutas individuais, seguindo a nomenclatura padrão:

```
<região><az>-<IP>-<YYYYMMDD>-<HHMM>.pcap.gz
```

Exemplo de arquivos:

```
datasets/e3/
├── af-south-1a-13.244.104.42-20231219-2011.pcap.gz
├── af-south-1a-13.244.104.42-20231219-2011.pcap.txt
├── af-south-1a-13.244.104.42-20231220-2011.pcap.gz
├── af-south-1a-13.244.104.42-20231220-2011.pcap.txt
├── ...
└── us-west-2b-54.191.47.68-20231217-2356.pcap.gz
```

- **~21.300 capturas `.pcap.gz`** elegíveis (≈42.600 arquivos contando os `.pcap.txt`),
  cobrindo **26 regiões AWS**, janela de ~outubro/2023 a ~fevereiro/2024.
- Cada arquivo segue a nomenclatura bruta completa:
  `<região><az>-<IP>-<YYYYMMDD>-<HHMM>.pcap.gz`.

O dataset e3 é o **dataset-alvo deste TCC** e é **elegível para amostragem
estratificada** (etapa 0).

### Datasets anteriores (removidos)

Os datasets `datasets/e1`, `datasets/e1_subset` e o dataset e3 original (agregados
por região `e3_<região>.pcap.gz` + `final_results/`) foram substituídos pela versão
bruta descrita acima.

---

## 2. Uso no pipeline

### Testes de desenvolvimento (amostra pequena)

A etapa 0 funciona diretamente com o e3 atual, pois os arquivos seguem a nomenclatura
bruta reconhecida por `FILENAME_RE`:

```sh
python3 src/0_select_representative_subset.py datasets/e3 \
    --output datasets/e3_subset --max-files 12 --clean
```

Depois disso, o pipeline segue normalmente:

```sh
python3 src/1_generate_tshark_csv.py datasets/e3_subset
zcat datasets/e3_subset/output.csv.gz \
    | venv/bin/python src/2_enrich_csv.py \
    | gzip > datasets/e3_subset/output.enriched.csv.gz
zcat datasets/e3_subset/output.enriched.csv.gz \
    | venv/bin/python src/6_shodan_enrich.py \
    | gzip > datasets/e3_subset/output.shodan.gz
zcat datasets/e3_subset/output.enriched.csv.gz \
    | venv/bin/python src/3_summarize_radiation.py \
    > datasets/e3_subset/output.tex
```

### Execução de produção (dataset completo do TCC)

```sh
python3 src/0_select_representative_subset.py datasets/e3 \
    --output datasets/e3_full --max-files 21326 --clean
```

Ou diretamente com todas as capturas:

```sh
other/full_etl.sh --dataset datasets/e3
```

### Regras de convívio com os dados

- A etapa 0 continua válida e necessária para qualquer conjunto com nomenclatura
  bruta (padrão `<região><az>-<IP>-<data>-<hora>`).
- Não processe o dataset completo durante testes de desenvolvimento.
- Prefira amostras pequenas e representativas (`--max-files` pequeno).
