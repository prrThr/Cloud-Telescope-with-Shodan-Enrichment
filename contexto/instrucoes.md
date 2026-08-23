# Instruções de contexto para agentes de IA

Este arquivo contém as instruções específicas para compreender e desenvolver o
projeto ibr-etl / Cloud Telescope.

Estas instruções complementam o `AGENTS.md`, localizado na raiz do projeto.

## 1. Objetivo do projeto

O objetivo deste projeto é realizar o enriquecimento do pipeline do Cloud Telescope,
originalmente desenvolvido no trabalho do professor Fabrício Bortuluzzi.

O projeto está relacionado ao TCC de Arthur Pereira.

Toda implementação deve considerar simultaneamente:

- o trabalho original;
- o TCC atual;
- a arquitetura existente;
- o pipeline já implementado;
- os dados efetivamente capturados;
- as decisões registradas durante o desenvolvimento.

Não implemente funcionalidades apenas porque parecem tecnicamente interessantes.
A implementação deve possuir relação clara com o objetivo do projeto.

---

## 2. Documentos de referência

Os principais documentos do projeto estão em `contexto/`.

### `Cloud_Telescope.md`

É o TCC do professor Fabrício Bortuluzzi.

Utilize este documento para compreender:

- o trabalho original;
- o funcionamento do Cloud Telescope;
- a metodologia original;
- a origem dos dados;
- conceitos utilizados no pipeline original.

É uma referência para compreender o sistema que este projeto pretende estender.

### `TCC_2_ArthurPereira_PosBanca.md`

É a escrita do TCC de Arthur Pereira.

É a principal referência conceitual e metodológica para o desenvolvimento deste projeto.

Antes de implementar uma funcionalidade relevante, verifique se ela está alinhada com:

- objetivos do TCC;
- metodologia;
- problemas identificados;
- resultados pretendidos;
- escopo definido.

Não altere arbitrariamente o escopo definido no TCC.

As implementações devem estar alinhadas com os objetivos, metodologia e direcionamentos apresentados no `Cloud_Telescope.md`.

### `claude_memory.md`

Contém a memória e as conclusões obtidas pela IA Claude durante tentativas anteriores de desenvolvimento.
Utilize este arquivo como contexto auxiliar.

Ele pode conter:

- decisões anteriores;
- hipóteses;
- problemas encontrados;
- soluções testadas;
- limitações conhecidas;
- observações sobre o código.

As informações desse arquivo não devem ser consideradas automaticamente corretas.

Se houver conflito entre `claude_memory.md`, o código atual, os testes ou os documentos canônicos, investigue a situação antes de tomar uma decisão.

### `estrutura.md`

Contém a estrutura atual de arquivos do projeto.

Consulte-o antes de:

- criar arquivos;
- remover arquivos;
- mover arquivos;
- alterar a organização dos diretórios;
- introduzir novos módulos.

Se a estrutura do projeto mudar, atualize `estrutura.md`.

### `pipeline.md`

Contém a descrição das etapas atuais do pipeline.

Quando uma implementação modificar:

- uma etapa existente;
- uma entrada;
- uma saída;
- o formato de dados;
- a ordem das etapas;
- dependências entre etapas;
- parâmetros;
- comportamento;

atualize `pipeline.md`.

---

## 3. Inspeção dos datasets

Os datasets estão localizados em:

```text
datasets/e1/
datasets/e3/
```

Eles contêm grande quantidade de dados e não devem ser lidos integralmente.

### Inspeção inicial obrigatória

Para compreender a estrutura dos arquivos capturados pelo telescópio, faça uma inspeção limitada:

- leia no máximo **10 arquivos** de `e1/`;
- leia no máximo **10 arquivos** de `e3/`.

O objetivo é apenas compreender a estrutura real dos dados.
A inspeção deve observar, quando relevante:

- formato;
- campos;
- cabeçalhos;
- separadores;
- codificação;
- estrutura das linhas;
- padrões de timestamps;
- endereços IP;
- portas;
- protocolos;
- informações de rede;
- características específicas de cada dataset.

### Restrições

Não:

- leia todos os arquivos;
- processe o dataset inteiro;
- carregue grandes arquivos integralmente na memória;
- faça varreduras desnecessárias;
- use os datasets completos para testes rotineiros.

Depois de compreender a estrutura, utilize preferencialmente:

- documentação;
- scripts existentes;
- amostras pequenas;
- resultados já processados;
- arquivos de contexto.

### backups/

O diretório `backups/` é inútil para o desenvolvimento.
Ignore-o completamente.
Não leia, processe ou utilize seus arquivos como fonte de informação.

---

## 4. Processo obrigatório antes de implementar

### Etapa 1 — compreender o contexto

Leia os documentos relevantes de `contexto/`.

Não é necessário ler documentos enormes integralmente quando a tarefa não exigir.
Faça leitura seletiva quando apropriado.

### Etapa 2 — compreender a estrutura

Consulte `contexto/estrutura.md` e confirme onde a alteração deve ser realizada.

### Etapa 3 — compreender o pipeline

Consulte `contexto/pipeline.md` e identifique:

- etapa afetada;
- entradas;
- saídas;
- consumidores;
- possíveis efeitos colaterais.

### Etapa 4 — verificar o código

Leia o código relacionado à alteração antes de modificá-lo.
Não substitua uma implementação existente sem compreender sua função.

### Etapa 5 — verificar o TCC

Consulte `contexto/TCC_2_ArthurPereira_PosBanca.md` quando a alteração estiver relacionada à metodologia, objetivos ou resultados do projeto.

### Etapa 6 — implementar

Faça a menor alteração necessária para atingir o objetivo.
Evite refatorações não relacionadas.

### Etapa 7 — testar

Execute testes apropriados à alteração.
Sempre que possível, utilize dados pequenos e controlados.

### Etapa 8 — documentar

Documente os testes, resultados e alterações conforme a seção abaixo.

---

## 5. Regra de implementação incremental

Priorize alterações pequenas, verificáveis e reversíveis.

Não implemente várias mudanças independentes simultaneamente quando isso dificultar identificar a causa de um eventual problema.

Quando uma tarefa possuir várias etapas:

1. compreenda o problema;
2. implemente uma parte;
3. teste;
4. verifique o resultado;
5. prossiga para a próxima parte.

Se uma decisão arquitetural importante for necessária, explique a consequência antes de realizar uma alteração ampla.

---

## 6. Testes

Toda implementação deve possuir uma estratégia de verificação.

Dependendo da alteração, os testes podem incluir:

- teste unitário;
- teste de integração;
- teste com amostra pequena;
- teste de formato;
- teste de entrada/saída;
- teste de regressão;
- execução de uma etapa específica do pipeline;
- comparação entre resultado esperado e resultado obtido.

Não é necessário criar testes artificiais apenas para aumentar a quantidade de testes.
O teste deve verificar efetivamente o comportamento implementado.

--- 

## 7. Documentação obrigatória após implementação

Sempre que uma implementação for realizada, crie ou atualize um arquivo `.md` dentro de `contexto/` documentando a implementação e seus testes.

A documentação deve conter, quando aplicável:

- Objetivo: Explique o que foi implementado e por quê.
- Alterações realizadas: Descreva os arquivos, módulos ou etapas modificados.
- Comportamento esperado: Descreva o que deveria acontecer após a implementação.
- Testes realizados: Registre os comandos, procedimentos ou cenários utilizados.
- Resultados esperados: Descreva o resultado que deveria ser obtido.
- Resultados obtidos: Descreva o resultado efetivamente observado.
- Problemas ou limitações: Registre falhas, comportamentos inesperados, limitações ou pontos que precisam de investigação futura.

--- 

## 8. Atualização do `pipeline.md`

Se a implementação alterar o pipeline, atualize o `contexto/pipeline.md`.

A atualização deve refletir o comportamento real do código, não apenas o comportamento
pretendido.

Não deixe a documentação do pipeline divergente da implementação.

--- 

## 9. Atualização do estrutura.md

Se arquivos ou diretórios forem:

- criados;
- removidos;
- renomeados;
- movidos;

atualize o `contexto/estrutura.md`.
A estrutura documentada deve representar a estrutura real do projeto.

---

## 10. Resultados esperados versus resultados obtidos

Não confunda expectativa com resultado experimental.

Utilize sempre uma distinção explícita:

```text
Resultado esperado:
...

Resultado obtido:
...
```

Se os resultados forem diferentes, não altere a documentação para fazer parecer que o teste passou.
Registre a divergência e investigue sua causa.

---

## 11. Preservação do trabalho existente

Não remova ou sobrescreva alterações existentes sem necessidade.

Antes de alterar um arquivo:

- verifique seu conteúdo atual;
- identifique alterações relevantes;
- preserve funcionalidades existentes;
- evite mudanças não relacionadas.

Não assuma que código aparentemente incompleto deve ser removido.

---

## 12. Credenciais e dados sensíveis

Nunca registre em documentação:

- API keys;
- tokens;
- senhas;
- credenciais;
- dados privados desnecessários.

Ao documentar comandos envolvendo credenciais, utilize placeholders seguros.

Exemplo:

```text
SHODAN_API_KEY=<configurada no ambiente>
```

Nunca registre o valor real.

---

## 13. Princípio geral

O objetivo principal do agente é compreender antes de modificar.

Prioridades:

- preservar a integridade do projeto;
- compreender os dados e o pipeline;
- manter alinhamento com o TCC;
- realizar alterações pequenas e verificáveis;
- testar as alterações;
- documentar os resultados;
- manter a documentação sincronizada com o código.

Quando houver incerteza relevante, não invente uma resposta.

Investigue o código, a documentação, os testes e os dados disponíveis antes de decidir.
