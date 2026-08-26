# ibr-etl — Cloud Telescope / Internet Background Radiation (IBR)

Pipeline de ETL que processa capturas de tráfego de rede (Internet Background Radiation,
"radiação de fundo" da internet) coletadas pelo telescópio Cloud Telescope — PCAPs de
honeypots em instâncias AWS — e as enriquece com dados geográficos (GeoIP), infraestrutura
AWS (awsipranges) e metadados OSINT (Shodan). É o projeto de TCC de Arthur Pereira, que
estende o trabalho original do prof. Fabrício Bortoluzzi.

## CRÍTICO — leia `contexto/instrucoes.md` antes de modificar o projeto

`contexto/instrucoes.md` contém as instruções específicas para agentes de IA trabalharem
neste projeto.

Antes de realizar qualquer modificação significativa:

1. Leia `contexto/instrucoes.md`.
2. Consulte os documentos de referência indicados nesse arquivo.
3. Consulte `contexto/estrutura.md` para compreender a organização atual.
4. Consulte `contexto/pipeline.md` para compreender o pipeline atual.
5. Verifique o código existente antes de propor uma nova implementação.
6. Não faça alterações baseadas apenas em suposições.

As instruções de `contexto/instrucoes.md` complementam este arquivo.

## Hierarquia da documentação (fonte única de verdade)

Cada informação tem **um único lugar canônico**. Não duplique regras entre arquivos;
atualize o documento responsável. Ordem de precedência em caso de conflito:

1. **Segurança e integridade** — nunca tocar em `datasets/` (leitura/exploração),
   nunca expor segredos. Inviolável, prevalece sobre qualquer outro documento.
2. **`AGENTS.md`** (este arquivo) — regras operacionais canônicas.
3. **`contexto/instrucoes.md`** — processo detalhado de trabalho (complementa o
   `AGENTS.md`; não pode contradizê-lo).
4. **Documentos vivos** — devem refletir a realidade atual do projeto e ser
   atualizados junto com o código: `contexto/pipeline.md`, `contexto/estrutura.md`,
   `contexto/dataset_e3.md`, `tests/exemplos_de_testes.md`.
5. **Referência conceitual** — `contexto/Cloud_Telescope.md`,
   `contexto/TCC_2_ArthurPereira_PosBanca.md` (definem escopo/metodologia; não
   descrevem a implementação corrente).
6. **Registros históricos auxiliares** — `contexto/implementacoes_e_testes.md`,
   `contexto/claude_memory.md`. Úteis como contexto, mas **não-canônicos**: em
   conflito com código, testes ou documentos vivos, investigue antes de decidir.

O arquivo `.opencode/rules.md` é apenas um redirecionamento para este documento;
não contém regras próprias.

## Datasets

O dataset está disponível em:

- `datasets/e3` — Dataset 3: capturas brutas com nomenclatura padrão
  `<região><az>-<IP>-<YYYYMMDD>-<HHMM>.pcap.gz` (~21.300 capturas, ~42.600
  arquivos incluindo `.pcap.txt`).

O dataset possui grande volume de dados e não deve ser lido ou processado
integralmente apenas para compreender sua estrutura.

### Regra geral

- **Não liste, leia, abra ou escaneie arquivos de `datasets/`** (inclui `ls`, `find`,
  `glob`, `du`, `rg`, `cat`, `zcat`, `read`). São ~37 GiB de dados opacos; o opencode
  já respeita o `.gitignore`, cuidado apenas com comandos `bash` crus.
- Para compreender a estrutura dos dados, use a documentação (`AGENTS.md`,
  `contexto/dataset_e3.md`, `contexto/estrutura.md`) e as regex
  `FILENAME_RE`/`REGION_AZ_RE` em `src/0_select_representative_subset.py`.
  Exceção: executar as etapas do pipeline sobre um diretório de execução ou subconjunto
  (amostra pequena), validando apenas códigos de saída e contagens, sem ler o conteúdo
  gerado.
- Não processe o dataset completo durante testes de desenvolvimento.
- Prefira amostras pequenas e representativas.

### Nomenclatura das capturas

A nomenclatura padrão é:

```
<região>-<az>-<IP>-<YYYYMMDD>-<HHMM>.pcap.gz
```

Exemplo: `af-south-1a-13.244.104.42-20231219-2011.pcap.gz`

Representa:
região: `af-south-1`
Availability Zone: `a`
IP: `13.244.104.42`
data: `2023-12-19`
horário: `20:11`

A etapa 0 (`src/0_select_representative_subset.py`) reconhece esta nomenclatura
para amostragem estratificada por região. Consulte `FILENAME_RE` e `REGION_AZ_RE`
em `src/0_select_representative_subset.py` quando precisar compreender ou alterar
o parser dos nomes.

## Contexto do projeto (leia antes de qualquer modificação)

Os documentos ficam em `contexto/`; seus papéis estão definidos na hierarquia acima:

- `contexto/instrucoes.md` — processo detalhado de trabalho para agentes de IA.
- `contexto/Cloud_Telescope.md` — TCC do prof. Bortoluzzi (base do projeto).
- `contexto/TCC_2_ArthurPereira_PosBanca.md` — TCC do Arthur (especificação a seguir).
- `contexto/pipeline.md` — etapas atuais do pipeline (vivo; atualizar junto com o código).
- `contexto/estrutura.md` — árvore de arquivos do projeto (viva; atualizar ao mover/criar/remover).
- `contexto/dataset_e3.md` — diferenças entre datasets e como usá-los nos testes (vivo).
- `contexto/implementacoes_e_testes.md` — registro histórico de implementações/testes.
- `contexto/claude_memory.md` — lições de sessões anteriores (auxiliar, não-canônico).

Os dois TCCs são grandes; leia-os seletivamente (grep/parágrafos) conforme a tarefa,
não do início ao fim.

## Estrutura do repositório

- `src/` — pipeline principal
- `contexto/` — documentação, TCC e instruções do projeto
- `other/` — utilitários auxiliares (agregação de pcaps, ETL completo, por região).
- `backups/` — **inútil, ignore completamente.**
- `logs/` — saídas de log e cache de execuções (ex: `shodan_cache.json`, `cacheinfo.txt`).
- `Docker/` — `Dockerfile` + `docker-compose.yml`.
- `tests/` — testes e provas de conceito.
- `venv/` — ambiente virtual local (ignore).
- `GeoIP2-City.mmdb` — base MaxMind GeoIP licenciada, usada pelo pipeline
  (`src/2_enrich_csv.py`). A gratuita (`GeoLite2-City.mmdb`) existe apenas em
  `backups/` (obsoleta).

Todos os scripts do pipeline devem resolver caminhos relativos ao `PROJECT_ROOT` e não depender do diretório de trabalho atual.

## Pipeline

Fluxo: extração (tshark) → enriquecimento (GeoIP + AWS) → enriquecimento Shodan →
consumidores paralelos (resumo, grafo, MySQL).

| Etapa | Arquivo | Entrada → Saída |
|---|---|---|
| 0. Amostragem | `src/0_select_representative_subset.py` | seleciona subconjunto representativo do dataset (estratificação por região + seleção sistemática), cria `subset_manifest.{csv,json}` |
| 1. Extração | `src/1_generate_tshark_csv.sh` | `dir/*.pcap.gz` → `dir/output.csv.gz` (colunas `time,ip.src,ip.dst,tcp.dstport,tcp.flags.str,udp.dstport,icmp.type`) |
| 2. Enriquecimento | `src/2_enrich_csv.py` | `output.csv.gz` → `output.enriched.csv.gz` (adiciona GeoIP de origem e destino + região AWS; descarta janelas de exclusão) |
| 3. Resumo | `src/3_summarize_radiation.py` | `output.enriched.csv.gz` → `output.tex` (agregações de radiação) |
| 4. Grafo | `src/4_generate_graph.py` | CSV de IPs únicos → Cypher para Neo4j |
| 5. MySQL | `src/5_import_mysql.py` | CSV enriquecido → banco MySQL |
| 6. Shodan | `src/6_shodan_enrich.py` | `output.enriched.csv.gz` → `output.shodan.gz` (campos 18–27: org, ISP, ASN, OS, portas, CPEs, CVEs, tags, hostnames, last_seen) |

As etapas 3–5 consomem o mesmo CSV enriquecido **em paralelo** (não sequencialmente).
A etapa 6 adiciona campos nas posições 18–27 do CSV (após `awsregion`).

### Exemplos de execução

```sh
python3 src/0_select_representative_subset.py datasets/e3 --output datasets/e3_subset --max-files 48 --clean
src/1_generate_tshark_csv.sh datasets/e3_subset
zcat datasets/e3_subset/output.csv.gz | python src/2_enrich_csv.py | gzip > datasets/e3_subset/output.enriched.csv.gz
zcat datasets/e3_subset/output.enriched.csv.gz | python src/6_shodan_enrich.py | gzip > datasets/e3_subset/output.shodan.gz
zcat datasets/e3_subset/output.enriched.csv.gz | python src/3_summarize_radiation.py > datasets/e3_subset/output.tex
```

> A etapa 0 reconhece a nomenclatura padrão `<região><az>-<IP>-<data>-<hora>` e
> funciona com o `datasets/e3` atual (capturas brutas). Para testes rápidos, use
> `--max-files` pequeno. Detalhes: `contexto/dataset_e3.md`.

## Contrato de pipeline
- **stdin/stdout com CSV** — cada etapa lê CSV da entrada padrão e emite CSV (compactado com `gzip`) na saída padrão. Preserve isso em novos módulos.
- Os scripts devem resolver caminhos relativos ao `PROJECT_ROOT`, nunca ao `CWD`.

## Convenções de código

- Todos os scripts resolvem caminhos relativos ao `PROJECT_ROOT` (via `os.path.dirname(os.path.dirname(os.path.abspath(__file__)))`), nunca ao `CWD`.
- Código e comentários em português (padrão do repositório).
- Sem comentários adicionais em código novo, a menos que solicitado.
- Preserve o estilo e a arquitetura existentes.
- Evite refatorações não relacionadas à tarefa solicitada.
- Antes de criar uma nova abstração, verifique se já existe uma implementação equivalente.
- Não altere contratos de entrada/saída sem verificar todos os consumidores afetados.

## Segurança e credenciais

- `.env` contém segredos (`SHODAN_API_KEY`). NUNCA comite, logue ou exponha segredos.
- Créditos da API Shodan são limitados: cache local por IP (`logs/shodan_cache.json`, gravado em lote via `--cache-save-every`) e rate-limit (1 req/s, com retentativas limitadas) são decisões de design, não opcionais.
- O hardcoded de API key foi corrigido; não reintroduza chaves no código.

## Verificação

Não há framework de lint/test padronizado no projeto. Verifique mudanças executando o script/pipeline afetado com uma amostra pequena (ex: `--max-files 12`), como nos exemplos acima. Antes de executar pipelines, remova `output*.csv*` antigos do diretório de destino.

Os comandos de teste para a situação atual do pipeline estão documentados em
`tests/exemplos_de_testes.md`. **Mantenha esse arquivo atualizado** sempre que o
pipeline mudar (novas etapas, argumentos, formatos de CSV/cache, modos de uso) —
corrija exemplos desatualizados em vez de ignorá-los.

## Documentação

Sempre que uma implementação alterar o comportamento do projeto:

1. atualize a documentação correspondente;
2. atualize `contexto/pipeline.md` se uma etapa do pipeline tiver sido alterada;
3. registre os testes realizados e seus resultados em documentação dentro de `contexto/`, conforme `contexto/instrucoes.md`.

Não considere uma implementação concluída enquanto os testes necessários e sua
documentação não tiverem sido realizados.

## Git

### Política de Branches e Commits

Toda implementação, alteração ou correção realizada pela IA deverá ser desenvolvida em uma branch exclusiva, seguindo o padrão **Conventional Branch**.

A IA nunca deverá realizar alterações diretamente na branch `main`, nem executar `push` para qualquer branch remota. Todo o desenvolvimento deverá ocorrer em branches separadas da `main`, garantindo isolamento das mudanças e permitindo revisão humana antes da integração.

### Regras de Branches

- Cada nova implementação deve iniciar com a criação de uma nova branch.
- O nome da branch deve seguir o padrão **Conventional Branch**.
- A branch deve representar claramente o objetivo da alteração, utilizando convenções como:
  - `feat/<descricao-da-feature>`
  - `fix/<descricao-do-bug>`
  - `chore/<descricao-da-manutencao>`
  - `refactor/<descricao-da-refatoracao>`

### Regras de Commits

Todos os commits realizados pela IA devem seguir o padrão **Conventional Commits**.

Os commits devem:
- Possuir uma categoria válida (feat, fix, docs, refactor, test, chore, entre outras).
- Ter uma descrição objetiva da alteração realizada.
- Manter histórico de mudanças claro e rastreável.

Exemplos:

```
feat(auth): adiciona suporte a login social

fix(api): corrige validação de token expirado

refactor(database): simplifica camada de acesso aos dados
```

### Fluxo de Finalização

Ao concluir uma implementação, a IA deverá:

1. Garantir que todas as alterações estejam na branch criada para a tarefa.
2. Verificar se os commits seguem o padrão **Conventional Commits**.
3. Solicitar a criação de um **Pull Request** da branch de implementação para a main.
4. Aguardar a revisão e aprovação humana antes de qualquer integração.

A aprovação ou rejeição do **Pull Request** é responsabilidade exclusiva do humano responsável pelo repositório.

A IA não realiza merge, não aprova Pull Requests e não interfere na branch `main` em nenhuma circunstância.

## Idioma

Comunique-se com o usuário em português.
