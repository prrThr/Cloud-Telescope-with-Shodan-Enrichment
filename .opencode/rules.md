# Regras operacionais do ibr-etl

Estas regras valem para **todas** as sessões neste projeto. Em caso de conflito com
outras instruções, estas têm prioridade.

## 1. Nunca toque em `datasets/`

- `datasets/e1`, `datasets/e3`, `datasets/*/aggregated` e `datasets/e3/final_results`
  contêm ~37 GiB de capturas binárias `.pcap.gz`. São dados opacos e processados.
- Proibido: `ls`, `find`, `glob`, `du`, `rg`, `read`, `cat`, `zcat` (salvo a exceção
  abaixo) ou qualquer comando que liste, conte, abra ou resuma arquivos dentro de
  `datasets/`.
- O opencode respeita o `.gitignore`, então `datasets/` nem aparece nas ferramentas de
  listagem. Cuidado apenas com comandos `bash` crus.
- Para entender a estrutura dos arquivos, leia `AGENTS.md` (nomenclatura), a regex
  `FILENAME_RE`/`REGION_AZ_RE` em `src/0_select_representative_subset.py` e
  `contexto/estrutura.md`. Não explore o diretório.

## 2. `backups/` é inútil

Ignore `backups/`. Ele contém versões antigas/obsoletas de scripts. Não use como
referência.

## 3. Contexto do projeto

Antes de modificar código, leia os documentos em `contexto/` conforme a tarefa:
- `TCC_2_ArthurPereira_PosBanca.md` — especificação do TCC (base).
- `Cloud_Telescope.md` — TCC original (base).
- `claude_memory.md` — lições de sessões anteriores.
- `instrucoes.md` / `estrutura.md` — instruções e estrutura.

## 4. Contrato do pipeline

- Cada etapa lê CSV via **stdin** e emite CSV via **stdout** (compactado com `gzip`).
- Caminhos relativos a `PROJECT_ROOT`, nunca ao diretório de trabalho.
- Código e comentários em português; não adicione comentários além do necessário.

## 5. Segurança

- `.env` contém `SHODAN_API_KEY`. Nunca comite, logue ou exponha segredos.
- API Shodan tem créditos limitados: manter cache por IP e rate-limit (1 req/s, backoff
  em 429). Não remover essas proteções.

## 6. Verificação

Não há framework de lint/test. Valide mudanças com uma amostra pequena do pipeline
(ex: `--max-files 12`) e removendo `output*.csv*` antigos do diretório de destino antes.

## 7. Manutenção de `tests/exemplos_de_testes.md`

`tests/exemplos_de_testes.md` documenta como testar a **situação atual** do pipeline
e é um "living spec". Sempre que o pipeline mudar (novas etapas, novos argumentos,
alterações de formato de CSV/cache, novos modos de uso), **atualize este arquivo**
para refletir o estado novo. Corrija exemplos desatualizados em vez de ignorá-los.
Crie ou ajuste os comandos de verificação junto com qualquer mudança de código.

## 8. Idioma

Responda ao usuário em português.
