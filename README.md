# ibr-etl

## Cloud Telescope - Internet Background Radiation - Procedimento de Enriquecimento de PCAP

### Requisitos
Funciona em Linux, Linux dentro do WSL (Windows Subsystem for Linux) ou Docker.

Copie todos os arquivos PCAP para um único diretório.

Requisitos:
- Utilitários Unix padrão: `gzip` e `cat`.
- `tshark` (instalação: `sudo apt install tshark`)
- `GeoIP2-City.mmdb`, que pode ser obtido em: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
- Python **3.11** e os seguintes pacotes Python:
    - `geoip2`
    - `awsipranges`
    - `shodan` (não possui suporte para Python 3.11+)
- Instalação do `pip`:
    - `$ sudo apt install python3-pip`
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

## Referências

- [Arquitetura em Terraform (ibr-iac)](https://github.com/lucasbeiler/ibr-iac)
- [Scripts etl (ibr-etl)](https://github.com/bortoluzzi/ibr-etl) (versão original do repositório atual)