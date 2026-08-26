# ibr-etl

## Cloud Telescope - Internet Background Radiation - Procedimento de Enriquecimento de PCAP

### Requisitos
Funciona em Linux, Windows Subsystem for Linux ou Docker.

Copie todos os arquivos `.pcap` para um único diretório.

Requisitos:
- Utilitários Unix padrão: `gzip` e `cat`.
- `tshark` (instalação: [neste link](https://tshark.dev/setup/install/))
- `GeoLite2-City.mmdb` (ou `GeoIP2-City.mmdb` caso licenciada), que pode ser obtido em: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
- `pip` para instalação das dependências do python (guia em como instalar [neste link](https://pip.pypa.io/en/stable/installation/#ensurepip))
    - Para distros Debian/Ubuntu basta `sudo apt install python3-pip`
- Python **3.11** e os seguintes pacotes Python:
    - `geoip2`
    - `awsipranges`
    - `shodan` (não possui suporte para Python 3.11+)
- Instalação dos pacotes:
    - `pip install setuptools wheel shodan geoip2 awsipranges python-dotenv`

### Geração de consultas Cypher para Neo4J

Se você pretende utilizar o **Neo4J**, descomente as linhas relevantes no arquivo `2_enrich_csv.py`.

### Trabalhando com uma pequena amostra para testar tudo

Se você quiser testar o pipeline com 100 pacotes antes de processar um lote grande:

- `zcat big.pcap.gz | editcap -r - sample.pcap 1-100`
- `gzip sample.pcap`
- Certifique-se de que não exista nenhum arquivo PCAP grande neste diretório de testes; caso contrário, ele também será processado.
- Teste a amostra: `tshark -r sample.pcap`

### Subconjunto representativo (etapa 0)

Para evitar processar o dataset completo no desenvolvimento local, use o estágio de amostragem do pipeline. Ele seleciona arquivos por região e distribui os pontos no tempo de forma sistemática.

A etapa 0 reconhece a nomenclatura padrão (`<região><az>-<IP>-<data>-<hora>`) e funciona com o `datasets/e3` atual (capturas brutas). Para testes rápidos, use `--max-files` pequeno. Detalhes: `contexto/dataset_e3.md`.

- `python3 src/0_select_representative_subset.py datasets/e3 --output datasets/e3_subset --max-files 48 --clean`
- `time src/1_generate_tshark_csv.sh datasets/e3_subset`
- `time zcat datasets/e3_subset/output.csv.gz | python src/2_enrich_csv.py | gzip > datasets/e3_subset/output.enriched.csv.gz`

Se quiser uma amostra ainda menor para depuração rápida, reduza `--max-files` para 12 ou 24.

### Exemplo rápido de comandos ETL (Extract-Transform-Load)

- Remova arquivos `output.csv` ou `output.csv.gz` anteriores, caso existam de execuções passadas.
- O script `1_generate_tshark_csv.sh` espera encontrar um conjunto de arquivos `pcap` compactados com `gzip` no mesmo diretório. Como resultado, ele gera um único arquivo compactado chamado `output.csv.gz`. Ajuste conforme necessário.

### Exemplo de execução ETL sequencial com medição de tempo em cada etapa

- `time ./1_generate_tshark_csv.sh`
- `time zcat output.csv.gz | python 2_enrich_csv.py | gzip > output.csv.enriched.gz`
- `time zcat output.csv.enriched.gz | python 3_summarize_radiation.py > output.tex`

### Caso você tenha gerado grafos no `2_enrich_csv.py`

```sh
$ zcat output_enriched.csv.gz | python 4_generate_graph.py | gzip > output.cypher.cql.gz
```

### Comandos úteis

```bash
zcat <arquivo>.pcap.gz | tshark -r - | head -n 5
```

```bash
zcat <arquivo>.pcap.gz | tcpdump -r - -n | head -n 5
```


## Referências

- [Arquitetura em Terraform (ibr-iac)](https://github.com/lucasbeiler/ibr-iac)
- [Scripts etl (ibr-etl)](https://github.com/bortoluzzi/ibr-etl) (versão original do repositório atual)