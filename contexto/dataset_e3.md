# Dataset e3 — estrutura e uso no pipeline

Este documento descreve a estrutura atual do dataset e como utilizá-lo no pipeline.

---

## 1. Estrutura do dataset

### `datasets/e3_raw` — capturas brutas individuais

Contém as capturas brutas individuais do Cloud Telescope, seguindo a nomenclatura padrão:

```
<região><az>-<IP>-<YYYYMMDD>-<HHMM>.pcap.gz
```

Exemplo de arquivos:

```
datasets/e3_raw/
├── af-south-1a-13.244.104.42-20231219-2011.pcap.gz
├── af-south-1a-13.244.104.42-20231219-2011.pcap.txt
├── af-south-1a-13.244.104.42-20231220-2011.pcap.gz
├── af-south-1a-13.244.104.42-20231220-2011.pcap.txt
├── ...
└── us-west-2b-54.191.47.68-20231217-2356.pcap.gz
```

- **~21.300 capturas `.pcap.gz`** elegíveis (≈42.600 arquivos contando os `.pcap.txt`),
  cobrindo **26 regiões AWS**, janela de ~outubro/2023 a ~fevereiro/2024.
- Cada arquivo é uma captura individual de um sensor específico em uma data/hora
  específica. Um sensor (IP público) por região, com capturas escalonadas ao longo
  do tempo.
- **Elegível para amostragem estratificada** (etapa 0), pois os arquivos seguem a
  nomenclatura bruta reconhecida por `FILENAME_RE`.

### `datasets/e3_full` — capturas agregadas por região

Contém as capturas agregadas por região AWS. Cada arquivo é a **concatenação de
todas as capturas individuais** da mesma região em um único `.pcap.gz`:

```
datasets/e3_full/
├── e3_af-south-1.pcap.gz
├── e3_ap-east-1.pcap.gz
├── ...
└── e3_us-west-2.pcap.gz
```

- **26 arquivos** (um por região AWS), resultantes da junção de todas as capturas
  individuais daquela região.
- A aggregação mistura tráfego de diferentes datas/horários da mesma região,
  resultando em maior diversidade de IPs de destino (públicos e privados) em
  comparação com uma captura individual.
- **Não é elegível para amostragem estratificada** (etapa 0), pois os arquivos não
  seguem a nomenclatura bruta. O `full_etl.sh` faz o link direto por ordem alfabética
  quando a etapa 0 não encontra nomenclatura elegível.

### Diferença comportamental importante

Capturas individuais do `e3_raw` podem conter apenas IPs de destino privados
(depending da janela temporal e do tráfego capturado), resultando em fallback
GeoIP/AWS em 100% das linhas. O `e3_full`, ao agregar múltiplas capturas da
mesma região, tende a misturar tráfego com IPs públicos e privados, reduzindo
a taxa de fallback. Para testes que exigem IPs públicos de destino (GeoIP
significativo), prefira o `e3_full`.

### Datasets anteriores (removidos)

Os datasets `datasets/e1`, `datasets/e1_subset` e o dataset e3 original (agregados
por região `e3_<região>.pcap.gz` + `final_results/`) foram substituídos pelas
versões descritas acima.

---

## 2. Uso no pipeline

### Testes de desenvolvimento (amostra pequena)

A etapa 0 funciona diretamente com o `e3_raw`, pois os arquivos seguem a nomenclatura
bruta reconhecida por `FILENAME_RE`:

```sh
python3 src/0_select_representative_subset.py datasets/e3_raw \
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
python3 src/0_select_representative_subset.py datasets/e3_raw \
    --output datasets/e3_full --max-files 21326 --clean
```

Ou diretamente com todas as capturas:

```sh
other/full_etl.sh --dataset datasets/e3_raw
```

### Teste rápido com `e3_full` (agregado)

```sh
other/full_etl.sh -d datasets/e3_full -n 1 -p 60 -q 60
```

### Regras de convívio com os dados

- A etapa 0 continua válida e necessária para qualquer conjunto com nomenclatura
  bruta (padrão `<região><az>-<IP>-<data>-<hora>`).
- Não processe o dataset completo durante testes de desenvolvimento.
- Prefira amostras pequenas e representativas (`--max-files` pequeno).
