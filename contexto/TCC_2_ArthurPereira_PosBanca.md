---
titulo: "Avaliação do Shodan como plataforma de aquisição de inteligência sobre ameaças cibernéticas capturadas pelo Telescópio de Nuvem"
autor: "Arthur de Oliveira Pereira"
orientador: "Fabricio Bortoluzzi, Dr."
instituicao: "Universidade do Vale do Itajaí — Escola Politécnica — Curso de Ciência da Computação"
local_data: "São José, junho/2026"
area_concentracao: "Sistemas de Computação"
linha_pesquisa: "Análise de tráfego de redes"
palavras_chave: ["Telescópio de Nuvem", "Radiação de Fundo da Internet", "Shodan", "cibersegurança", "enriquecimento de dados"]
paginas_originais: 39
fonte: "Convertido a partir de TCC_2_ArthurPereira_PosBanca.pdf via extração de texto (pdftotext/pdfplumber), sem OCR"
---

# Avaliação do Shodan como Plataforma de Aquisição de Inteligência sobre Ameaças Cibernéticas Capturadas pelo Telescópio de Nuvem

**Autor:** Arthur de Oliveira Pereira
**Orientador:** Fabricio Bortoluzzi, Dr.
**Instituição:** Universidade do Vale do Itajaí — Escola Politécnica — Curso de Ciência da Computação
**Local/Data:** São José, junho/2026
**Área de Concentração:** Sistemas de Computação
**Linha de Pesquisa:** Análise de tráfego de redes
**Palavras-chave:** Telescópio de Nuvem, Radiação de Fundo da Internet, Shodan, cibersegurança, enriquecimento de dados
**Número de páginas (original):** 39

---

## Resumo

A Internet Background Radiation (IBR) consiste no tráfego de rede não solicitado que circula continuamente pela Internet, originado por varreduras automatizadas, worms, botnets e configurações incorretas de dispositivos. A coleta e análise desse tráfego permite identificar padrões de atividade maliciosa em escala global, sendo os telescópios de rede a principal ferramenta para essa observação passiva. O projeto Cloud Telescope (Telescópio de Nuvem) propôs uma arquitetura distribuída e nativa de nuvem que utiliza instâncias da Amazon Web Services (AWS) distribuídas em múltiplas regiões geográficas como sensores de captura de IBR, produzindo datasets de dezenas a centenas de milhões de eventos de rede. O pipeline de processamento associado realiza a extração, transformação e carga desses dados, enriquecendo cada pacote capturado com informações de geolocalização e identificação de infraestrutura AWS. Contudo, o pipeline atual não contempla a correlação dos endereços IP de origem com bases externas de inteligência, o que limita a profundidade analítica sobre o perfil dos emissores da radiação. Este trabalho tem como objetivo estender o pipeline de processamento mediante a integração da API de Open Source Intelligence (OSINT) Shodan, de forma a enriquecer os dados coletados com metadados adicionais sobre os endereços IP de origem, incluindo tipo de dispositivo, serviços expostos e Common Vulnerabilities and Exposures (CVEs). A metodologia compreende a reprodução do pipeline existente, a análise técnica aprofundada da API do Shodan e seus metadados, o desenvolvimento de um módulo de integração compatível com a arquitetura atual e a análise quantitativa do ganho informacional proporcionado. Como resultado, espera-se demonstrar a viabilidade técnica da integração proposta e evidenciar o incremento na capacidade analítica do pipeline para a caracterização das fontes de IBR.

## Abstract

*(Título original: Evaluation of Shodan as a platform for acquiring cyber threat intelligence captured by the Cloud Telescope)*

Internet Background Radiation (IBR) refers to unsolicited network traffic that continuously circulates through the Internet, originating from automated scans, worms, botnets, and misconfigured devices. The collection and analysis of this traffic allow the identification of malicious activity patterns on a global scale, with network telescopes being the primary tool for this passive observation. The Cloud Telescope project proposed a distributed and cloud-native architecture that utilizes Amazon Web Services (AWS) instances distributed across multiple geographic regions as IBR capture sensors, producing datasets containing tens to hundreds of millions of network events. The associated processing pipeline performs the extraction, transformation, and loading (ETL) of these data, enriching each captured packet with geolocation information and AWS infrastructure metadata. However, the current pipeline does not include the correlation of source IP addresses with external intelligence databases, which limits the analytical depth regarding the profile of IBR sources. This work aims to extend the processing pipeline through the integration of the Shodan Open Source Intelligence (OSINT) API, in order to enrich the collected data with additional metadata about source IP addresses, including device type, exposed services, known vulnerabilities (CVEs) and security-related indicators. The methodology consists of the reproduction of the existing pipeline, the in-depth technical analysis of the Shodan API and its metadata, the development of an integration module compatible with the current architecture, and the quantitative analysis of the additional information provided. As a result, it is expected to demonstrate the technical viability of the proposed integration and highlight the increase in the pipeline's analytical capacity for characterizing IBR sources.

## Lista de Abreviaturas e Siglas

| Sigla | Significado |
|---|---|
| API | Application Programming Interface |
| AS | Autonomous System |
| AWS | Amazon Web Services |
| CLI | Command Line Interface |
| CPE | Common Platform Enumeration |
| CSV | Comma-Separated Values |
| CVE | Common Vulnerabilities and Exposures |
| CTI | Cyber Threat Intelligence |
| DDoS | Distributed Denial of Service |
| DNS | Domain Name System |
| EC2 | Elastic Compute Cloud |
| ETL | Extract Transform Load |
| HTTP | Hypertext Transfer Protocol |
| IaC | Infrastructure as Code |
| IBR | Internet Background Radiation |
| ICMP | Internet Control Message Protocol |
| IoT | Internet of Things |
| IP | Internet Protocol |
| IPv4 | Internet Protocol versão 4 |
| ISP | Internet service provider |
| JSON | JavaScript Object Notation |
| NAT | Network Address Translation |
| OSINT | Open Source Intelligence |
| PCAP | Packet Capture |
| SSH | Secure Shell |
| SSL | Secure Sockets Layer |
| TCC | Trabalho de Conclusão de Curso |
| TCP | Transmission Control Protocol |
| TLS | Transport Layer Security |
| UDP | User Datagram Protocol |
| URL | Uniform Resource Locator |

## Lista de Símbolos

| Símbolo | Significado |
|---|---|
| `/` | Prefixo de máscara de sub-rede (notação CIDR) |
| `$` | Representação de comando em interface de linha de comando (CLI) |

---

# 1 Introdução

A Internet moderna enfrenta desafios crescentes relacionados à segurança cibernética, com ameaças que se manifestam através de tráfego malicioso não solicitado conhecido como Internet Background Radiation (IBR). Este fenômeno, analogamente à radiação cósmica de fundo, refere-se ao fluxo persistente de pacotes que chegam a dispositivos conectados à Internet sem que tenham sido requisitados (MOORE et al., 2004). A análise deste tipo de tráfego tem se mostrado fundamental para a detecção precoce de campanhas globais de malware, propagação de botnets e identificação de padrões de ataques cibernéticos (PANG et al., 2004).

Historicamente, a coleta de IBR tem sido realizada através de Network Telescopes (Telescópios de Rede), dispositivos dedicados configurados para capturar passivamente pacotes direcionados a blocos de endereços de internet protocol (IP) não utilizados (IRWIN, 2011). Estas infraestruturas têm contribuído significativamente para a compreensão de ameaças que afetam a internet em escala global, auxiliando na detecção de eventos como a propagação do worm Conficker, a evolução do botnet Mirai e seus variantes, além de ataques massivos de negação de serviço (WUSTROW et al., 2010; BENSON et al., 2015).

Entretanto, o modelo tradicional do telescópio de rede apresenta limitações significativas. Primeiro, existe uma escassez crítica de endereços IPv4 disponíveis para alocação, uma vez que o espaço de endereçamento de 32 bits do protocolo já foi completamente distribuído pelas autoridades regionais (RICHTER et al., 2015). Segundo, os telescópios convencionais são geograficamente estáticos, vinculados à localização física da instituição que os opera, o que limita a capacidade de observação distribuída de ameaças com características geopolíticas específicas (BORTOLUZZI et al., 2023). Terceiro, apenas poucas instituições acadêmicas e de pesquisa possuem recursos e blocos de IP ociosos suficientes para operacionalizar estes sistemas de captura.

Como alternativa às limitações dos telescópios de rede tradicionais, BORTOLUZZI et al. (2025) propuseram o Cloud Telescope (Telescópio de Nuvem), uma arquitetura efêmera, distribuída e nativa em nuvem para coleta de IBR. Esta abordagem aproveita a infraestrutura global de provedores de serviços em nuvem, como Amazon Web Services (AWS), para implantar sensores de captura em múltiplas regiões geográficas simultaneamente. No experimento validador de cinco meses, o telescópio de nuvem coletou 530 milhões de eventos de tráfego não solicitado distribuídos por 26 regiões da AWS, abrangendo todos os continentes, demonstrando a viabilidade técnica e escalabilidade da arquitetura proposta.

## 1.1 Problematização

Apesar do sucesso na coleta distribuída de grandes volumes de dados, o pipeline atual de processamento e enriquecimento dos datasets do Telescópio de Nuvem apresenta limitações significativas. Atualmente, o enriquecimento dos endereços IP capturados restringe-se ao uso de bibliotecas de geolocalização (GeoIP) e identificação de ranges da AWS (awsipranges), fornecendo apenas informações básicas sobre a localização geográfica e origem em infraestrutura de nuvem dos IPs observados.

Esta abordagem, embora útil para análises agregadas, não fornece inteligência sobre a natureza técnica dos emissores, como o tipo de dispositivo (Internet of Things [IoT], servidores, roteadores), arquitetura de hardware e, principalmente, as vulnerabilidades associadas, conhecidas como Common Vulnerabilities and Exposures (CVE). Sem esses metadados, torna-se inviável caracterizar o perfil tecnológico das botnets que utilizam a IBR para propagação, resultando em uma análise limitada ao nível geoespacial, mas desprovida de profundidade técnica sobre a superfície de ataque observada.

## 1.2 Formulação do Problema

Neste contexto, identifica-se uma lacuna relevante: os datasets massivos produzidos pelo Telescópio de Nuvem permanecem subutilizados devido à simplicidade do pipeline de enriquecimento atual. Existe uma oportunidade de transformar esses registros brutos em Cyber Threat Intelligence (CTI) acionável através da correlação com fontes externas de Open Source Intelligence (OSINT). Diante disso, este trabalho busca responder à seguinte questão: **Como a integração de Application Programming Interfaces (API) de OSINT ao pipeline do Telescópio de Nuvem pode incrementar a caracterização técnica e o valor informacional dos eventos de radiação de fundo da internet?**

A literatura recente em análise de IBR tem demonstrado o valor de técnicas de enriquecimento mais sofisticadas. SHAIKH et al. (2018) utilizaram plataformas de OSINT como Shodan e Censys para correlacionar tráfego de radiação com dispositivos específicos da IoT, identificando 285.478 dispositivos IoT vulneráveis envolvidos em ataques. ZAKROUM et al. (2022) aplicaram técnicas de aprendizado de máquina sobre dados enriquecidos de telescópios para desenvolver modelos preditivos de ameaças cibernéticas. Estes trabalhos evidenciam que a integração de múltiplas fontes de inteligência amplifica significativamente a capacidade analítica e o valor dos dados coletados.

### 1.2.1 Solução Proposta

A solução proposta fundamenta-se na necessidade de expandir as capacidades analíticas do projeto Telescópio de Nuvem através do desenvolvimento de um pipeline de enriquecimento estendido utilizando a API do Shodan. Esta ferramenta foi selecionada por ser a mais popular plataforma de OSINT para identificação de recursos online, tendo boa reputação e acessibilidade acadêmica, já que seu plano acadêmico fornece um volume de dados superior ao de concorrentes para fins de pesquisa. A integração permitirá a extração de metadados adicionais sobre os IPs maliciosos observados, incluindo informações sobre tipos de dispositivos, serviços expostos, vulnerabilidades conhecidas, certificados digitais e histórico de atividades. Este enriquecimento possibilitará análises qualitativas mais profundas sobre os padrões de ataque observados, melhor caracterização de campanhas de malware e botnets, além de contribuir para o estabelecimento de correlações entre eventos de radiação e infraestruturas específicas de atacantes.

A importância deste trabalho manifesta-se em múltiplas dimensões. Do ponto de vista metodológico, o desenvolvimento de técnicas reproduzíveis de enriquecimento de dados para análise de IBR incrementa a profundidade analítica das investigações de ameaças em CTI. Do ponto de vista prático, os datasets enriquecidos resultantes terão maior valor para a comunidade de pesquisa em segurança cibernética, facilitando estudos sobre evolução de ameaças, análise de influência geopolítica em ataques e desenvolvimento de mecanismos de detecção mais eficazes. Adicionalmente, a arquitetura de enriquecimento desenvolvida é extensível, permitindo a incorporação futura de novas fontes de inteligência conforme novas APIs e serviços de OSINT se tornem disponíveis.

## 1.3 Objetivos

Este trabalho contém um objetivo geral e cinco objetivos específicos.

### 1.3.1 Objetivo Geral

O objetivo geral deste trabalho é avaliar a plataforma Shodan como ferramenta para a aquisição de inteligência sobre ameaças cibernéticas, mediante a integração de sua API ao pipeline de enriquecimento do Telescópio de Nuvem, de modo a mensurar o valor informacional dos eventos de IBR coletados.

### 1.3.2 Objetivos Específicos

1. Revisar as técnicas voltadas à aquisição de inteligência sobre ameaças cibernéticas, fundamentando o uso da ferramenta Shodan para a caracterização de emissores de IBR.
2. Integrar a técnica de enriquecimento técnico baseada na API do Shodan ao pipeline de processamento original do Telescópio de Nuvem, automatizando a correlação de eventos de rede com metadados de infraestrutura, software e hardware.
3. Aplicar o fluxo de processamento expandido a um subconjunto representativo do Dataset 3, realizando a identificação de tipos de dispositivos, serviços ativos e vulnerabilidades conhecidas associadas aos endereços IP capturados.
4. Desenvolver visualizações comparativas que demonstrem o ganho de inteligência obtido através do enriquecimento expandido, evidenciando percepções que não seriam possíveis com o pipeline original.
5. Documentar os subprodutos das etapas anteriores e analisar as vantagens auferidas pela integração.

## 1.4 Metodologia

A metodologia adotada para o desenvolvimento deste trabalho caracteriza-se como uma pesquisa aplicada de natureza exploratória e descritiva, fundamentada em uma abordagem quantitativa e experimental. O procedimento metodológico baseia-se no processo de Extract-Transform-Load (ETL) já consolidado no projeto Telescópio de Nuvem e divide-se em cinco fases lógicas e sequenciais.

Na fase inicial, realiza-se a revisão bibliográfica sobre IBR, o funcionamento de telescópios de rede e técnicas de enriquecimento de dados de rede. Simultaneamente, procede-se à reprodução local do pipeline de processamento existente, visando a compreensão técnica de seus componentes de extração de arquivos Packet Capture (PCAP) e enriquecimento geográfico. O sistema é testado com amostras do Dataset 3, estabelecendo-se uma linha de base para a quantificação do ganho informacional futuro. A amostragem é definida de forma estratificada por região da AWS e, dentro de cada estrato, os arquivos são selecionados de forma sistemática ao longo da linha do tempo das capturas, de modo a preservar diversidade geográfica e temporal sem exigir o processamento do dataset integral.

A segunda fase consiste na análise técnica e na parametrização da API do Shodan, considerando critérios de viabilidade para pesquisa acadêmica, como limites de requisição, qualidade dos metadados de dispositivos IoT e disponibilidade de informações sobre CVEs.

Na terceira fase, desenvolve-se o módulo de integração em Python como uma extensão modular ao pipeline original. O desenvolvimento foca na implementação de lógica de autenticação, mecanismos de cache local para preservação de créditos de consulta e tratamento de erros para garantir a resiliência no processamento de grandes volumes de eventos.

Na quarta fase, o pipeline expandido é aplicado a um subconjunto representativo do Dataset 3. Realiza-se a análise comparativa para mensurar o incremento de inteligência, focando na capacidade de identificar tipos de dispositivos e vulnerabilidades ativas que o pipeline básico não era capaz de detectar. Esse subconjunto é produzido por um estágio de pré-processamento independente, que seleciona arquivos representativos por região e por distribuição temporal, permitindo a execução local em escala reduzida.

Por fim, dedica-se a quinta fase à redação da monografia e à sistematização dos resultados, apresentando visualizações comparativas que demonstrem a viabilidade da arquitetura proposta para a geração de CTI.

### Cronograma

No Quadro 1 é apresentado o cronograma das atividades desenvolvidas durante o Trabalho de Conclusão de Curso (TCC) II.

| Atividade | Mar/2026 | Abr/2026 | Mai/2026 | Jun/2026 |
|---|:---:|:---:|:---:|:---:|
| Revisão bibliográfica | x | | | |
| Reprodução do pipeline atual localmente | | x | | |
| Estudo e seleção de API de OSINT | | | x | |
| Escrita do documento | | | | x |

*Quadro 1 - Cronograma de execução para o TCC II. Fonte: Autoria própria.*

No Quadro 2 consta o cronograma de atividades previstas para o TCC III.

| Atividade | Ago/2026 | Set/2026 | Out/2026 | Nov/2026 |
|---|:---:|:---:|:---:|:---:|
| Codificação do módulo de integração | x | | | |
| Execução e processamento de dados | | x | | |
| Análise e visualização de resultados | | | x | |
| Escrita final e preparação para defesa | | | | x |

*Quadro 2 - Cronograma de execução para o TCC III. Fonte: Autoria própria.*

### Análise dos Riscos

O TCC proposto apresenta 1 grande risco levantado que pode inviabilizar o trabalho. No Quadro 3 ele é apresentado juntamente com as medidas a serem tomadas para contornar as limitações.

| Risco | Probabilidade | Impacto | Gatilho | Plano de contingência |
|---|---|---|---|---|
| Lentidão no processamento de PCAPs | Média | Alto | Hardware pessoal limitado para processar os 530 milhões de eventos do Dataset 3. | Utilizar processamento paralelo e processar apenas um subconjunto representativo dos dados, conforme delimitado no escopo. |
| Dados históricos expirados | Alta | Baixo | API do Shodan limitar o acesso a dados de IPs capturados há mais de 6 meses (Dataset 3). | A possível obsolescência temporal dos metadados via APIs não compromete esta pesquisa, cujo foco é avaliar técnicas de enriquecimento de dados e o ganho informacional da integração do Shodan. Para aplicações em tempo real, o Telescópio de Nuvem permite replicar o método com conjuntos de dados mais recentes. |
| Sensibilidade jurídica na varredura ativa | Baixa | Alto | Realização inadvertida de escaneamento de portas direto contra atacantes. | Não realizar varreduras diretas. Utilizar exclusivamente o Shodan para obter informações de portas e banners de forma passiva. |

*Quadro 3 - Análise de riscos. Fonte: Autoria própria.*

Em síntese, a análise de riscos evidencia que o planejamento técnico e ético do trabalho provê os mecanismos necessários para contornar as limitações inerentes ao uso de ferramentas externas e ao processamento de grandes volumes de dados. A implementação de um sistema de cache local e o uso de processamento paralelo garantem a eficiência operacional e a preservação de créditos da API, enquanto a estratégia de auditoria passiva elimina vulnerabilidades jurídicas relacionadas à interação direta com potenciais atacantes.

Dessa forma, as medidas de contingência estabelecidas asseguram a integridade metodológica da pesquisa, demonstrando que a obsolescência temporal de certos metadados ou as restrições de hardware não comprometem o objetivo central de avaliar a eficácia do enriquecimento de dados para a geração de inteligência sobre ameaças cibernéticas.

---

# 2 Fundamentação Teórica

Neste capítulo são introduzidos os principais estudos e embasamentos utilizados na construção e na implementação do projeto. O primeiro tópico explica a Radiação de Fundo da Internet. O segundo tópico contextualiza a relevância que a análise de tráfego de rede tem para este projeto, bem como algumas técnicas associadas. O terceiro e quarto tópicos discorrem sobre os telescópios de rede e nuvem respectivamente. No quinto tópico são descritos os datasets gerados pelo Telescópio de Nuvem. Por fim, no sexto tópico, são apresentados os conceitos sobre Shodan.

## 2.1 Radiação de Fundo da Internet

A Radiação de Fundo da Internet, também referida pela sigla IBR (Internet Background Radiation) ou Ruído de Fundo da Internet, compreende o fluxo incessante de pacotes de rede não solicitados destinados a endereços Internet Protocol (IP) públicos. O termo, cunhado originalmente por Pang et al. (2004), é uma analogia à radiação cósmica de fundo e descreve um fenômeno onipresente que atinge qualquer dispositivo conectado à rede mundial de computadores, inclusive em faixas de endereçamento não utilizadas ou produtivas (PANG et al., 2004; BORTOLUZZI et al., 2025). Conforme estabelecido na literatura, a natureza da IBR pode ser segmentada em componentes benignos e maliciosos, dependendo das motivações de sua geração:

- **Tráfego benigno:** origina-se de falhas de configuração em sistemas e serviços de rede, tais como erros de Network Address Translation (NAT) ou Domain Name System (DNS), além da atividade de plataformas de censo da Internet, como o Shodan e o Censys, que realizam varreduras globais com fins legítimos de mapeamento e pesquisa (PANG et al., 2004; IRWIN, 2011; BORTOLUZZI et al., 2025).
- **Tráfego malicioso:** constitui a maior parte da IBR e é caracterizado pela intenção hostil (BORTOLUZZI et al., 2025). Este componente inclui varreduras automatizadas para identificação de vulnerabilidades, propagação de malwares autopropagáveis (worms) e a atividade de botnets, como a família Mirai, que buscam infectar dispositivos da IoT para orquestrar ataques de negação de serviço (WUSTROW et al., 2010; BENSON et al., 2015; BORTOLUZZI et al., 2025).
- **Retroespalhamento (Backscatter):** representa o tráfego de resposta enviado por vítimas de ataques de negação de serviço a endereços que foram forjados pelo atacante original por meio de IP spoofing (MOORE et al., 2006). Segundo Moore et al. (2006), como o sensor do telescópio recebe uma resposta a um pacote que ele nunca enviou, esse tráfego é categorizado como uma fonte distinta e inquestionável de radiação de fundo (MOORE et al., 2006; BORTOLUZZI et al., 2025).

## 2.2 Análise de Tráfego

A análise de tráfego transforma registros brutos de pacotes capturados em inteligência acionável. O processo inicia-se com a coleta de dados no formato PCAP, o padrão utilizado por bibliotecas como a libpcap e ferramentas como tcpdump e tshark. A literatura estabelece duas dimensões principais de análise:

1. **Análise Quantitativa:** Foca na distribuição estatística do tráfego. Avalia o volume de pacotes por protocolo (com predominância histórica do Transmission Control Protocol [TCP]), portas de destino mais sondadas (como Telnet/23 e Hypertext Transfer Protocol [HTTP]/80) e a geolocalização dos emissores por país de origem. Esta análise revela tendências de crescimento da radiação proporcional à expansão da adoção da Internet.
2. **Análise Qualitativa:** Investiga a carga útil (payload) dos pacotes para caracterizar intenções hostis. Através da inspeção de comandos capturados em sensores interativos (honeypots), é possível identificar tentativas de login por força bruta, Uniform Resource Locator (URL) de servidores de download de malware e assinaturas específicas de botnets.

A análise eficiente depende do processo de ETL, que organiza dados não estruturados em bases consultáveis. Embora útil para identificar de onde partem as ameaças, a análise convencional de tráfego é limitada na caracterização profunda técnica dos dispositivos emissores, o que demanda o enriquecimento desses dados com fontes externas de inteligência.

## 2.3 Telescópios de Rede

Um telescópio de rede, ou network telescope, é um sistema de monitoramento passivo projetado para observar eventos em larga escala na internet através da captura de tráfego destinado a espaços de endereçamento IP roteáveis, porém, não utilizados. A premissa fundamental é que, como esses endereços não possuem serviços legítimos ou hosts ativos, qualquer tráfego recebido por eles é, por definição, não solicitado e potencialmente malicioso, compreendendo varreduras de worms, botnets, retroespalhamento de ataques Distributed Denial of Service (DDoS) ou falhas de configuração.

A resolução e a probabilidade de detecção de um telescópio de rede dependem diretamente da sua abertura (*aperture*), ou seja, do número de endereços IP monitorados. Um telescópio com um bloco /8 (aproximadamente 16 milhões de endereços) tem maior probabilidade de observar eventos globais sutis do que um bloco /16. Além da dimensão do espaço de endereçamento, a literatura classifica esses sistemas de acordo com o nível de interatividade com o emissor:

1. **Passivo:** O modo padrão, onde o sensor apenas registra o pacote sem responder, mantendo-se indetectável.
2. **Baixa interação:** O sensor completa o 3-way handshake do protocolo TCP para observar o comportamento inicial da fonte antes de encerrar a conexão.
3. **Média a alta interação (Honeypots):** O sensor emula serviços reais (como Telnet ou HTTP) para capturar payloads, comandos de exploração e binários de malware.

A Figura 1 mostra o Telescópio de Rede como um servidor de computador ou estação de trabalho padrão ao qual foi atribuído um intervalo de endereços IP públicos. O tráfego produtivo é roteado através do firewall em direção à Rede Local (Local Area Network). Somente a porção ociosa do intervalo de endereços IP é efetivamente encaminhada para o Telescópio de Rede, que registra os pacotes recebidos no formato de arquivo PCAP, em um armazenamento secundário, para análise posterior.

> **[Figura 1 — Arquitetura do Telescópio de Rede. Fonte: Bortoluzzi et al. (2025)]**
> Diagrama de fluxo: `Internet` → `Router` → dois ramos: (a) `Firewall` → `Local Area Network`; (b) tráfego ocioso ("Unfiltered Public IP addresses or CIDR Block") → `Network Telescope`, que executa `$tcpdump > file` e grava uma sequência de arquivos `.pcap`.

Apesar de sua utilidade, os telescópios de rede tradicionais enfrentam limitações severas, como a escassez de endereços IPv4, que torna caro e difícil alocar grandes blocos para pesquisa. Além disso, são geograficamente estáticos, o que pode introduzir vieses nas medições baseados na localização física e no Sistema Autônomo (AS) onde o telescópio está inserido. Essas limitações motivam a transição para arquiteturas de telescópios em nuvem e a necessidade de enriquecimento de dados via OSINT para compensar a visibilidade técnica limitada da captura passiva.

## 2.4 Telescópios de Nuvem

Diferente dos modelos tradicionais estáticos, o Telescópio de Nuvem é definido como uma arquitetura nativa em nuvem, distribuída e efêmera. Sua existência justifica-se por três pilares fundamentais. O primeiro é a escassez de IPv4, pois a exaustão do espaço de endereçamento de 32 bits tornou financeiramente inviável ou tecnicamente impossível para muitas instituições alocarem grandes blocos ociosos para pesquisa. O segundo é a efemeridade e custo, onde utiliza instâncias do tipo Spot (recursos ociosos de provedores como AWS), sendo possível lançar frotas de sensores com descontos de até 90%, tornando a pesquisa de larga escala acessível. E por fim, dispersão geográfica: a implantação distribuída em múltiplas regiões (como as 26 regiões AWS utilizadas no projeto) permite capturar variantes geopolíticas de ataques que sensores estáticos não conseguiriam observar.

> **[Figura 2 — Instância de um sensor do Telescópio de Nuvem. Fonte: Bortoluzzi et al. (2025)]**
> Diagrama de fluxo, dentro de uma `Cloud Region` → `Virtual Private Cloud` → `Subnet`: `Internet Background Radiation` → `Gateway` → `Open Security Group` → `Sensor` → `Data` (`$tcpdump > file`, arquivos `.pcap`) → `Global Bucket Stockholm`.

A operacionalização desta arquitetura depende essencialmente de Infraestrutura como Código (IaC), especificamente o uso de ferramentas como Terraform. Isso garante que o telescópio possa ser replicado, escalado ou reconstruído rapidamente em resposta a eventos de término de instâncias pelo provedor. Enquanto o telescópio de rede tradicional foca na abertura do bloco de IPs, o telescópio de nuvem foca na distribuição e diversidade dos pontos de observação.

## 2.5 Datasets do Telescópio de Nuvem

A arquitetura do Telescópio de Nuvem gerou, até o momento, três conjuntos de dados principais, resultantes de experimentos conduzidos entre 2023 e 2024. Esses datasets refletem diferentes configurações de rede e objetivos de pesquisa, variando desde provas de conceito passivas até a implementação de sensores de alta interação.

### 2.5.1 Dataset 1 (maio de 2023)

O primeiro dataset foi produzido durante uma observação de 31 dias em maio de 2023, servindo como prova de conceito para a arquitetura distribuída. A frota de sensores consistiu em 26 instâncias Elastic Compute Cloud (EC2) da AWS (uma por região comercialmente disponível na época), operando em modo puramente passivo. O experimento capturou 21 milhões de eventos de rede, com uma predominância de tráfego TCP (17 milhões de pacotes), seguido por Internet Control Message Protocol (ICMP) com 3 milhões e UDP. As portas TCP mais visadas foram a 23 (Telnet), 22 (Secure Shell [SSH]) e 80 (HTTP).

### 2.5.2 Dataset 2 (agosto e setembro de 2023)

O segundo experimento, com duração de 47 dias, representou uma expansão significativa na escala de captura, acumulando 10 bilhões de eventos de rede e totalizando cerca de 900 gigabytes de dados brutos. A infraestrutura foi ampliada para 260 instâncias (10 por região AWS) e introduziu, pela primeira vez, um componente interativo de honeynet. Foram implementados respondedores de alto nível em Rust para as portas TCP/23 e TCP/80, permitindo registrar comandos de infecção emitidos por botnets como Mirai, Mozi e Sora.

### 2.5.3 Dataset 3 (outubro de 2023 a fevereiro de 2024)

O terceiro dataset resulta de uma captura passiva de longa duração (5 meses), operando com 130 instâncias (5 por região AWS). Este experimento gerou aproximadamente 531 milhões de eventos de rede registrados no formato PCAP. A distribuição dos protocolos mantém o padrão observado anteriormente: 80% do tráfego é composto por datagramas TCP, 16% por mensagens ICMP e 4% por UDP.

Pela sua extensão temporal e diversidade geográfica, o **Dataset 3** foi selecionado como o objeto de estudo para este trabalho. A análise incidirá sobre um subconjunto representativo desta massa de dados, visando demonstrar como a integração de APIs de OSINT pode enriquecer os metadados dos endereços IP de origem que, originalmente, contam apenas com informações básicas de geolocalização e identificação de infraestrutura de nuvem.

## 2.6 Shodan

O Shodan é um motor de busca lançado em 2009, projetado especificamente para identificar dispositivos e aplicações em execução acessíveis pela rede mundial de computadores. Diferente de motores de busca tradicionais, como o Google, que indexam páginas web, o Shodan foca na camada de infraestrutura de IoT, sendo capaz de localizar servidores, impressoras, webcams, sistemas de controle industrial (SCADA) e diversos outros dispositivos conectados.

### 2.6.1 Funcionamento e Arquitetura

O funcionamento do Shodan baseia-se em uma varredura contínua do espaço de endereçamento IPv4. O sistema utiliza centenas de módulos que implementam lógicas específicas de protocolos para tentar estabelecer conexões com endereços IP e portas gerados de forma aleatória. Uma vez estabelecida a conexão, o motor realiza um processo denominado *banner grabbing*, que consiste em capturar a resposta enviada pelo serviço (o *banner*).

Esses *banners* são fundamentais para a análise de segurança, pois frequentemente revelam metadados críticos, tais como: versões de software e servidores (ex: Apache, PHP, OpenSSH), sistemas operacionais, fabricantes de hardware, presença de CVEs, configurações de chaves criptográficas em serviços como SSH e certificados Secure Sockets Layer (SSL) e Transport Layer Security (TLS).

> **[Figura 3 — Arquitetura do funcionamento da plataforma Shodan. Fonte: Autoria própria]**
> Fluxo em 5 etapas: (1) Varredura do espaço IPv4 — geração aleatória de IPs e portas (ex.: `203.0.113.10:22`, `198.51.100.25:80`, `192.0.2.55:443`); (2) Tentativa de conexão; (3) Alvos (IP:Porta) classificados por protocolo — `22/TCP SSH`, `80/TCP HTTP`, `443/TCP HTTPS`; (4) Banner grabbing (resposta do serviço) — ex.: `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6`, `HTTP/1.1 200 OK Server: Apache/2.4.56 (Ubuntu)`, `HTTP/2 200 OK Server: nginx/1.20.1 SSL: TLSv1.3 Cert: Let's Encrypt`; (5) Armazenamento e indexação dos banners no motor de busca Shodan.

A Figura 3 demonstra superficialmente como funciona a plataforma Shodan.

### 2.6.2 Recursos de Busca e Filtragem

A plataforma oferece capacidades avançadas de filtragem e análise de dados. Por meio de *facets* (facetas), é possível obter uma visão estatística da distribuição de valores para propriedades específicas, como os países com maior número de servidores ou as organizações (Internet Service Provider [ISP]) com mais ativos expostos. O acesso aos dados pode ser feito via interface web, linha de comando (também referida como Command Line Interface [CLI]) ou API, sendo o consumo de dados controlado por um sistema de créditos de consulta e de varredura.

A Figura 4 mostra o retorno da busca pelo IP 8.8.8.8 (DNS primário do Google Public DNS) através do consumo da API disponível para Python. Neste retorno há dados essenciais como IP, país, organização responsável pelo IP, ASN e provedor de internet (ISP).

**Figura 4 - Retorno do consumo da API do Shodan** *(Fonte: Autoria própria)*

```text
$ python ip_data.py
IP: 8.8.8.8
País: United States
Organização: Google LLC
ASN: AS15169
ISP: Google LLC
```

Este retorno foi possível graças ao código a seguir, o qual importa a biblioteca do Shodan, carrega a chave da API através das variáveis de ambiente do sistema operacional e retorna os valores de acordo com os parâmetros dados em `host.get`.

**Figura 5 - Código de demonstração da API do Shodan** *(Fonte: Autoria própria)*

```python
import os
import shodan
from dotenv import load_dotenv

load_dotenv()
api_key = os.getenv("SHODAN_API_KEY")
api = shodan.Shodan(api_key)

ip = "8.8.8.8"

try:
    host = api.host(ip)

    print("IP:", host["ip_str"])
    print("País:", host.get("country_name"))
    print("Organização:", host.get("org"))
    print("ASN:", host.get("asn"))
    print("ISP:", host.get("isp"))

except shodan.APIError as e:
    print("Erro:", e)
```

Conforme ilustrado na Figura 5, a implementação encarregada do consumo da API do Shodan apresenta uma estrutura simplificada, uma vez que o propósito desta etapa reside na demonstração da recuperação de metadados técnicos fundamentais e habitualmente disponibilizados pela plataforma. Para expandir o pipeline atual com dados relevantes, sua complexidade aumentará gradualmente.

A imagem a seguir (Figura 6) é uma demonstração de busca pelo mesmo IP (8.8.8.8), mas através da interface web do Shodan. Nela é mostrada apenas uma parte da página gerada após a busca devido à alta quantidade de informações retornadas. Nesta busca são retornados dados essenciais como domínio (DNS), país de origem, cidade, organização responsável pelo IP, provedor de internet (ISP) e ASN.

> **[Figura 6 — Demonstração da interface web do Shodan. Fonte: Autoria própria]**
> Captura de tela de shodan.io para o IP `8.8.8.8`, seção "General Information": Hostnames: `dns.google`; Domains: `dns.google`; Country: `United States`; City: `Mountain View`; Organization: `Google LLC`; ISP: `Google LLC`; ASN: `AS15169`.

### 2.6.3 Relação com a Pesquisa

No âmbito deste trabalho, o Shodan desempenha um papel central na etapa de reconhecimento passivo. Esta fase, que é a primeira no processo de auditoria de segurança, visa coletar o máximo de informações sobre o alvo sem que haja interação direta ou envio de pacotes para o sistema de destino.

O Shodan permite que especialistas em segurança identifiquem a superfície de ataque de uma organização de forma externa, expondo dispositivos que podem estar com configurações padrão, sem autenticação ou executando software obsoleto e vulnerável. Além disso, a ferramenta possibilita a realização de estudos em larga escala, essenciais para caracterizar o estado da segurança cibernética em contextos específicos, como a rede brasileira, onde softwares sem suporte há anos continuam prevalentes.

---

# 3 Trabalhos Relacionados

Este capítulo tem por objetivo a apresentação de trabalhos relacionados que abordam temas de IBR, infraestruturas de telescópios de rede baseadas em computação em nuvem e métodos de enriquecimento de dados para a geração de inteligência sobre ameaças cibernéticas.

## 3.1 Processo de Busca dos Trabalhos Correlatos

O levantamento foi realizado em bases de dados reconhecidas pela comunidade acadêmica, incluindo IEEE Xplore, ACM Digital Library, Science Direct, Sbc Open Lib e Google Scholar. A estratégia de busca utilizou combinações de palavras-chave em língua portuguesa e inglesa, tais como Internet Background Radiation, Network Telescope, Cloud Telescope, Open Source Intelligence, Data Enrichment e Shodan.

O critério de inclusão priorizou publicações recentes, preferencialmente dos últimos cinco anos, para capturar a evolução das arquiteturas de monitoramento distribuído e o uso de ferramentas nativas de nuvem. Foram selecionados estudos que apresentam similaridade metodológica com o projeto Telescópio de Nuvem ou que exploram técnicas de enriquecimento de dados de rede para a geração de inteligência sobre ameaças cibernéticas. Foram destacados quatro trabalhos principais por sua relação direta com a infraestrutura utilizada ou pela aplicação prática da ferramenta Shodan no contexto de análise de tráfego.

## 3.2 Cloud Telescope: An Ephemeral, Distributed, and Cloud-Native Architecture for Collecting Internet Background Radiation

O trabalho principal e referência central desta pesquisa é o desenvolvido por Bortoluzzi, Irwin e Westphall (2025), no qual é apresentada a arquitetura do Telescópio de Nuvem. Os autores propuseram um paradigma inovador de observação passiva da rede mundial de computadores, utilizando uma infraestrutura efêmera e distribuída em 26 regiões da AWS. O estudo validou o método através de um experimento de cinco meses, resultando na coleta de 530 milhões de eventos de rede e demonstrando que a capilaridade geográfica da nuvem permite capturar variantes de ataques que telescópios estáticos tradicionais não conseguem observar.

A pesquisa de Bortoluzzi et al. (2025) detalhou o comportamento da IBR sob os aspectos de protocolos, revelando a predominância de 80% de tráfego TCP, e introduziu a análise de influência geopolítica nos ataques. Este trabalho é a base fundamental deste TCC, uma vez que o enriquecimento proposto via API do Shodan incidirá diretamente sobre o pipeline de dados e sobre o Dataset 3 gerado pelos autores mencionados. A integração de fontes de inteligência externa é citada por Bortoluzzi como uma frente de trabalho futuro necessária para elevar a profundidade analítica sobre o perfil técnico dos atacantes.

## 3.3 Análise da Radiação de Fundo da Internet por Captura Distribuída em Telescópio de Nuvem

Complementando a fundação técnica, Beiler (2023) realizou a primeira análise aprofundada de tráfego utilizando a infraestrutura do Telescópio de Nuvem. O foco do autor residiu na classificação quantitativa e estatística dos eventos capturados em 2023, estabelecendo os primeiros rankings de portas mais sondadas e países de origem. Beiler (2023) demonstrou a viabilidade do uso de IaC para a replicação do telescópio, porém limitou o enriquecimento dos endereços IP à geolocalização básica. O presente trabalho expande a contribuição de Beiler (2023) ao automatizar a extração de metadados técnicos dos dispositivos emissores, permitindo uma transição da análise estatística para a análise qualitativa técnica.

Conforme ilustrado na Figura 7, o fluxo operacional compreende a recepção da radiação de fundo da internet pelos sensores distribuídos em sub-redes da AWS, o registro dos pacotes em formato PCAP e o posterior armazenamento centralizado em um *bucket* global do Amazon S3. Essa representação arquitetural demonstra como a dispersão geográfica é tecnicamente viabilizada por meio de IaC, permitindo o processamento de volumes massivos de dados para a identificação de padrões estatísticos de tráfego.

> **[Figura 7 — Diagrama arquitetural detalhado. Fonte: Adaptado de Beiler (2023)]**
> Variante multi-sensor do diagrama da Figura 2: dentro de `Cloud Region` → `Virtual Private Cloud` → `Subnet`, `Internet Background Radiation` → `Gateway` → `Open Security Group` → múltiplos `Sensor` em paralelo → `Data` (`$tcpdump > file`, arquivos `.pcap`) → `Global Bucket Stockholm`.

## 3.4 An Exploratory Analysis on the Impact of Shodan Scanning Tool on the Network Attacks

Tundis, Modo Nga e Mühlhäuser (2021) investigaram o impacto de ferramentas de varredura pública online, especificamente o Shodan, na ocorrência de ataques de rede. Os autores destacam que o Shodan é uma das plataformas mais populares para a identificação de recursos da IoT e infraestruturas conectadas, operando através de técnicas de SYN scanning e banner grabbing para coletar metadados de serviços. O estudo propõe um modelo de análise que utiliza as informações fornecidas por essas ferramentas para caracterizar o perfil técnico de dispositivos sem a necessidade de interação direta, permitindo uma auditoria de segurança do tipo *contactless* que contorna limitações impostas por legislações de diversos países a testes de intrusão tradicionais.

A pesquisa de Tundis et al. (2021) fundamenta o uso de campos como Common Platform Enumeration (CPE) para identificação de classes de aplicações e CVE para a correlação com falhas de segurança conhecidas. Este trabalho diferencia-se do autor mencionado ao transpor essa base teórica para o contexto de telescópios de nuvem. Enquanto Tundis focou na influência das atualizações do Shodan sobre o comportamento dos atacantes, esta pesquisa foca na automação da integração desses metadados técnicos ao pipeline de processamento do Telescópio de Nuvem, visando transformar registros brutos de radiação de fundo em inteligência de ameaças acionável e detalhada.

Como demonstra no diagrama da Figura 8, os autores esquematizam o ecossistema de inteligência em que o Shodan atua como facilitador para o reconhecimento de recursos, permitindo a extração de metadados técnicos das vítimas para a geração de relatórios de ameaças. Este esquema visual justifica a adoção de auditorias do tipo *contactless*, servindo de base teórica para a integração da API do Shodan ao pipeline de processamento automatizado pretendido nesta pesquisa.

> **[Figura 8 — Modelo de análises. Fonte: Tundis et al. (2021)]**
> Diagrama conceitual com nós `Online Scanning Tool (OST)`, `Victim`, `Hackers or Criminals` e `Platform analysis`. Relações (algumas marcadas com "?", indicando questões investigadas pelo estudo original): OST → dados de varredura ("Online Scanning Tool Scanning Data") → Platform analysis; relação incerta entre OST e Victim; `Hackers or Criminals` → "Attacking the Victim" → Victim; relação incerta entre Victim e a etapa de monitoramento ("Monitoring the Victim and the Online Scanning Tool Scanning Data") dentro de Platform analysis; Platform analysis → "Analyzed Data and report generation".

## 3.5 Análise Comparativa

Os trabalhos selecionados demonstram uma evolução clara na observação da IBR. Enquanto Bortoluzzi et al. (2025) e Beiler (2023) estabeleceram a arquitetura distribuída e a validação quantitativa da radiação capturada, o estudo de Tundis et al. (2021) forneceu o embasamento sobre as capacidades técnicas do Shodan para a extração de inteligência qualitativa. Observa-se que, apesar de Bortoluzzi et al. (2025) citarem o enriquecimento OSINT como um trabalho futuro necessário, o nível de detalhamento técnico sobre vulnerabilidades e perfis de dispositivos ainda não foi implementado nos estudos anteriores sobre o Telescópio de Nuvem.

Diferentemente dos trabalhos correlatos, esta pesquisa propõe a fusão dessas duas frentes: a infraestrutura moderna e distribuída do Telescópio de Nuvem com a profundidade analítica dos metadados de CPE e CVE discutidos por Tundis et al. (2021). O diferencial reside na automação deste fluxo, superando a análise meramente estatística ou geográfica e entregando uma caracterização técnica robusta dos emissores da Radiação de Fundo da Internet através de uma interface de auditoria passiva.

| Característica | Trabalho 3.2 | Trabalho 3.3 | Trabalho 3.4 | Este Trabalho |
|---|---|---|---|---|
| Natureza da captura | Passiva e interativa | Passiva e interativa | Dados de varredura pública | Passiva |
| Ambiente de implantação | Nuvem (AWS) | Nuvem (AWS) | Internet pública | Nuvem (AWS) |
| Nível de enriquecimento | Geográfico e Infraestrutura | Geográfico e Volumétrico | Técnico (CVE e CPE) | Técnico (CVE e CPE) |
| Uso de APIs OSINT | Não (trabalho futuro) | Não | Shodan | Shodan |
| Foco da análise | Arquitetura cloud-native | Padrões estatísticos de tráfego | Impacto de ferramentas de busca | Automação de CTI |
| Referência | Bortoluzzi et al. (2025) | Beiler (2023) | Tundis et al. (2021) | Pereira (2026) |

*Quadro 4 - Trabalhos relacionados. Fonte: Autoria própria.*

O Quadro 4 representa as principais características e focos dos trabalhos relacionados. O próximo capítulo é dedicado à modelagem detalhada do projeto, sendo apresentado um panorama completo deste.

---

# 4 Projeto

O presente capítulo detalha a concepção técnica da extensão do pipeline de dados do projeto Telescópio de Nuvem. A descrição abrange a visão geral da solução, a análise detalhada dos requisitos necessários para a automação do enriquecimento informacional e as premissas de projeto que orientam o desenvolvimento do artefato de software.

## 4.1 Visão Geral do Sistema

O sistema proposto atua como um módulo complementar ao fluxo de ETL existente, operando na camada de transformação e enriquecimento de dados técnicos. A arquitetura fundamenta-se na extração de endereços IP de origem contidos no Dataset 3 para a realização de consultas assíncronas à API do Shodan. O objetivo central é transpor a limitação da análise puramente geográfica, agregando camadas de inteligência sobre a natureza tecnológica dos emissores de radiação através de uma interface de auditoria passiva e *contactless*.

O fluxo operacional inicia-se com a leitura de registros estruturados de rede, seguida pela identificação de endereços únicos para otimização de consultas. O módulo de integração comunica-se com os servidores do Shodan para resgatar metadados de infraestrutura, os quais são processados e correlacionados com bases de vulnerabilidades conhecidas. Ao final do processo, o sistema consolida as informações enriquecidas em formatos compatíveis com ferramentas de análise de dados, permitindo a caracterização detalhada da superfície de ataque observada pelos sensores de nuvem.

## 4.2 Análise de Requisitos

A definição dos requisitos é essencial para garantir que o módulo de integração cumpra os objetivos de extração de inteligência sem comprometer a eficiência do processamento de datasets massivos. A análise divide-se em capacidades funcionais, que descrevem o comportamento esperado do sistema, e qualidades não funcionais, que estabelecem as restrições técnicas e padrões de desempenho.

### 4.2.1 Requisitos Funcionais

Os requisitos funcionais elencados a seguir descrevem as operações que o sistema deve realizar para efetivar o enriquecimento dos dados de IBR:

| ID | Descrição |
|---|---|
| RF01 | O sistema deve processar arquivos de entrada resultantes do pipeline básico contendo endereços IPv4 de origem. |
| RF02 | O sistema deve identificar e agrupar endereços IP únicos para evitar redundância no consumo de créditos da API. |
| RF03 | O sistema deve realizar a autenticação segura junto à API do Shodan utilizando chaves de acesso fornecidas pelo usuário. |
| RF04 | O sistema deve obter metadados técnicos específicos, incluindo sistema operacional, portas abertas e serviços ativos. |
| RF05 | O sistema deve extrair informações de CPE e identificar CVEs associadas ao host. |
| RF06 | O sistema deve implementar um mecanismo de cache local para persistência de consultas já realizadas. |
| RF07 | O sistema deve organizar e exportar os dados enriquecidos em formatos estruturados como Comma-Separated Values (CSV) ou JavaScript Object Notation (JSON). |

### 4.2.2 Requisitos Não Funcionais

Os requisitos não funcionais definem os critérios de qualidade e as limitações tecnológicas que o módulo de software deve respeitar:

| ID | Descrição |
|---|---|
| RNF01 | O sistema deve ser desenvolvido utilizando a linguagem de programação Python na versão 3.11. |
| RNF02 | O sistema deve utilizar a biblioteca oficial Shodan para a comunicação com o motor de busca. |
| RNF03 | O sistema deve gerenciar os limites de requisição impostos pelo plano acadêmico da API de forma a evitar interrupções no processamento. |
| RNF04 | O sistema deve possuir tratamento de erros para falhas de rede, tempos de resposta expirados (timeouts) e consultas a endereços sem registros. |
| RNF05 | O sistema deve suportar operações em Linux ou containers Docker. |

## 4.3 Modelagem do Sistema

Neste tópico são apresentados os casos de uso do sistema, sua descrição, os atores envolvidos, suas metas e as etapas necessárias para alcançá-las.

### 4.3.1 Descrição da Modelagem

A modelagem do sistema fundamenta-se na arquitetura de um pipeline de ETL especializado no enriquecimento qualitativo de dados de rede. O processo de tratamento de dados inicia-se com o recebimento dos registros brutos capturados pelos sensores globais da AWS, os quais são previamente processados pelo utilitário tshark para extração dos endereços IPv4 de origem. O módulo em Python integra a API do Shodan para automatizar a coleta de metadados técnicos e CVEs, expandindo a análise atual que é restrita à geolocalização dos endereços IP.

A estrutura de dados para o armazenamento dos resultados contempla uma série de metadados fundamentais para a geração de CTI. O modelo de dados integra informações obtidas via banner grabbing e varreduras públicas, mapeando elementos como o sistema operacional, portas abertas e serviços ativos. Para a caracterização das ameaças, a modelagem prioriza a extração de identificadores de CPE para qualificar o hardware e software do emissor, além da correlação direta com o catálogo de CVEs para identificar falhas de segurança exploráveis.

O gerenciamento da base de dados local utiliza um mecanismo de cache baseado em estruturas de chave-valor, onde o endereço IP atua como chave primária para a persistência dos metadados OSINT. Esta abordagem garante a otimização do consumo de créditos acadêmicos e a eficiência no processamento de volumes massivos de eventos contidos no Dataset 3. O fluxo de saída é projetado para alimentar ferramentas de análise de dados, permitindo a transição de registros de pacotes para inteligência acionável sobre o perfil das botnets observadas.

## 4.4 Demonstração do Funcionamento da API do Shodan

A validação preliminar do módulo de integração é realizada através do script em Python denominado `6_shodan_enrich.py`, projetado para operacionalizar as consultas à API e gerenciar o fluxo de enriquecimento. O sistema dispõe de funcionalidades para a verificação de integridade da conta do pesquisador e para a simulação de consultas individuais, permitindo observar o ganho informacional antes do processamento em larga escala do Dataset 3.

### 4.4.1 Gerenciamento de Credenciais e Créditos

O controle operacional do módulo de integração inicia-se com a validação da chave de acesso e a verificação das permissões do plano associado à conta do pesquisador. Diferente de provedores de nuvem que adotam a tarifação por consumo, o Shodan utiliza um sistema de franquias mensais de créditos, as quais são renovadas automaticamente no primeiro dia de cada mês.

De acordo com as especificações técnicas da plataforma, a viabilidade deste trabalho fundamenta-se na distinção entre o que consome créditos de consulta e o que é disponibilizado de forma gratuita:

- **Consultas isentas de créditos:** Para o propósito deste trabalho, a característica mais relevante é que a consulta direta a um endereço IP específico (via endpoint `/shodan/host/{ip}`) não consome créditos de consulta. Além disso, buscas por strings puras sem filtros na primeira página de resultados e consultas de contagem (`count`) também são isentas de custos operacionais.
- **Ações que consomem créditos:** A dedução de 1 crédito de consulta ocorre apenas quando a consulta utiliza filtros de precisão (uso de dois-pontos, como `country:BR` ou `port:443`) ou quando há necessidade de paginação, ou seja, acessar da segunda página de resultados em diante para um mesmo termo.
- **Créditos de varredura:** São utilizados exclusivamente para quando se solicita que o Shodan realize a varredura de um IP em tempo real. Cada crédito permite a auditoria de um único host.

A viabilidade técnica deste projeto é garantida pelo uso do Plano Edu (Academic Upgrade), cujas especificações são comparadas aos demais planos no Quadro 5 a seguir:

| Recurso/Plano | Gratuito | Acadêmico | Vitalício | Comercial (assinatura) |
|---|---|---|---|---|
| Custo | Gratuito | Gratuito | R$ 49,00 (único) | A partir de $69/mês |
| Créditos de consulta por mês | 0 | 100 | 100 | 10.000+ |
| Créditos de varredura por mês | 0 | 100 | 100 | 5.120+ |
| Monitoramento (IPs) | Não possui | 16 | 16 | A partir de 5.120+ |
| Filtros (API) | Restrito | Todos (exceto vuln) | Todos (exceto vuln) | Completos |

*Quadro 5 - Comparativo de Planos e Limites da API do Shodan. Fonte: Adaptado de Shodan (2026).*

A Figura 9 a seguir mostra o retorno do sistema, que confirma a disponibilidade de 100 créditos de consulta e 100 créditos de scan para o plano do tipo `dev`, garantindo que o processamento do subconjunto de dados ocorra dentro dos limites operacionais da plataforma.

**Figura 9 – Modo `--info` do módulo de integração com a API do Shodan** *(Fonte: Autoria própria)*

```text
» python src/6_shodan_enrich.py --info
2026-06-02 17:15:10 [INFO] [API OK] Plano: 'dev' | Créditos de consulta: 100 | Créditos de scan: 100

── Informações da Conta Shodan ─────────────────
 Plano:                dev
 Créditos de consulta: 100
 Créditos de scan:     100
 Acesso HTTPS:         False
 Acesso a telnet:      False
```

### 4.4.2 Extração de Metadados em Modo de Demonstração

O modo de demonstração do módulo executa uma consulta individual para validar a recuperação de metadados. No exemplo é executada uma consulta sobre o endereço IP `185.220.101.45`. O processo de *lookup* identifica o host como pertencente a uma organização de tráfego de saída da rede Tor, localizado na cidade de Berlim, Alemanha. Através da técnica de *banner grabbing*, o módulo detecta a porta 80/TCP aberta e extrai o cabeçalho HTTP, o qual revela textualmente que o dispositivo atua como um roteador de saída Tor (*This is a Tor Exit Router*).

**Figura 10 - Modo `--demo` do módulo de integração com a API do Shodan** *(Fonte: Autoria própria)*

```text
$ python src/6_shodan_enrich.py --demo
# ======== 1. Identificação e Geolocalização ========
IP: 185.220.101.45
Organização: Network for Tor-Exit traffic.
ISP: Stiftung Erneuerbare Freiheit
ASN: AS60729
País: Germany (DE)
Cidade: Berlin, BE
Coordenadas: 52.52437, 13.41053
Código Postal: N/A
Domínios: ['for-privacy.net']
Hostnames: ['tor-exit-45.for-privacy.net']
Tags Shodan: []
Último scan: 2026-06-01T03:54:28.079820

# ======== 2. Sistema e Portas ========
OS detectado: Não identificado
Portas abertas: [80]
Serviços na resp: 1

# ======== 3. Serviços Detectados (Banner Grabbing) ========
[1] 80/tcp
    Banner: HTTP/1.0 200 OK
    Banner: Date: Mon, 01 Jun 2026 04:01:15 GMT
    Banner: Content-Type: text/html
    HTTP: 200 | título: This is a Tor Exit Router

# ======== 4. CVEs Conhecidos (0 encontrados) ========
Nenhum CVE registrado para este IP no Shodan.
(Nota: CVEs requerem plano acadêmico ou pago)

# ======== 5. Campos Adicionados ao CSV do Pipeline ========
2026-06-02 11:20:25 [INFO] [FOUND] 185.220.101.45 org='Network for Tor-Exit
traffic.' | portas=1 | serviços=1 | CPEs=0 | CVEs=0
```

| Campo CSV | Índice | Valor |
|---|---|---|
| `shodan_org` | [18] | Network for Tor-Exit traffic. |
| `shodan_isp` | [19] | Stiftung Erneuerbare Freiheit |
| `shodan_asn` | [20] | AS60729 |
| `shodan_os` | [21] | (vazio) |
| `shodan_open_ports` | [22] | 80 |
| `shodan_cpes` | [23] | (vazio) |
| `shodan_cves` | [24] | (vazio) |
| `shodan_tags` | [25] | (vazio) |
| `shodan_hostnames` | [26] | tor-exit-45.for-privacy.net |
| `shodan_last_seen` | [27] | 2026-06-01T03:54:28.079820 |

O resultado desta operação, descrito na Figura 10, ilustra o mapeamento dos metadados para os dez novos campos do dataset, localizados entre os índices 18 e 27 do arquivo de saída. O sistema organiza identificadores de CPE e listas de CVE, tratando a eventual ausência de registros históricos com o preenchimento de campos vazios. Esta funcionalidade assegura que a estrutura do arquivo final permaneça consistente para as etapas de análise estatística.

---

# 5 Considerações Finais

Este trabalho apresentou o progresso da implementação de uma técnica que enriquece os dados capturados pelo Telescópio de Nuvem utilizando a API do Shodan. A primeira parte discutiu conceitos teóricos e fundamentais sobre o fenômeno da IBR e a evolução das arquiteturas de monitoramento, desde os telescópios de rede tradicionais até o paradigma nativo em nuvem e distribuído proposto por Bortoluzzi et al. (2025).

A fundamentação teórica e a análise de trabalhos relacionados permitiram identificar que, embora o Telescópio de Nuvem possua uma infraestrutura massiva e geograficamente distribuída, o seu pipeline original de processamento carecia de profundidade técnica sobre a natureza dos emissores de radiação. Através da análise de requisitos e da modelagem de casos de uso apresentadas neste documento, definiu-se a concepção de um sistema de auditoria passiva e *contactless* capaz de transpor a análise puramente geoespacial para uma caracterização robusta de hardware, serviços e vulnerabilidades ativas (CVEs).

A demonstração do módulo em Python (`6_shodan_enrich.py`) validou a viabilidade técnica da integração, comprovando a capacidade de extrair metadados técnicos e estruturá-los em dez novos campos de inteligência dentro do conjunto de dados. Em suma, este projeto cumpre os objetivos da etapa de TCC-2 ao consolidar uma arquitetura extensível que fundamenta a transformação de registros brutos de rede em CTI acionável.

## 5.1 Próximas Etapas

Com a conclusão da fase de planejamento e documentação característica do TCC-2, a pesquisa avança para o estágio de execução técnica e experimental no TCC-3. As próximas etapas contemplam a materialização final do módulo de integração e a sua aplicação sistemática sobre um subconjunto representativo do Dataset 3, composto por milhões de eventos de rede.

O cronograma de desenvolvimento prevê a codificação completa das rotinas de tratamento de erros e a consolidação do mecanismo de cache local para a preservação de créditos acadêmicos. Adiante, está prevista a materialização da plataforma de análise através da geração de visualizações comparativas em formato CSV. O objetivo final dessas etapas é evidenciar quantitativamente o ganho informacional proporcionado pelo enriquecimento OSINT, entregando uma caracterização técnica detalhada das botnets que operam na radiação de fundo em escala global.

---

# Referências Bibliográficas

BEILER, Lucas Silvero. **Análise da radiação de fundo da internet por captura distribuída em telescópio de nuvem**. 2023. 71 f. Trabalho de Conclusão de Curso (Graduação em Ciência da Computação) – Escola Politécnica, Universidade do Vale do Itajaí, Itajaí, 2023.

BENSON, K. et al. Leveraging Internet background radiation for opportunistic network analysis. In: ACM SIGCOMM CONFERENCE ON INTERNET MEASUREMENT (IMC), 2015, Tokyo. **Proceedings [...]**. New York: ACM, 2015. p. 423-436.

BORTOLUZZI, Fabricio et al. Cloud telescope: A distributed architecture for capturing internet background radiation. In: IEEE INTERNATIONAL CONFERENCE ON CLOUD NETWORKING (CLOUDNET), 12., 2023. **Proceedings [...]**. Piscataway: IEEE, 2023. p. 77-85.

BORTOLUZZI, Fabricio; IRWIN, Barry; WESTPHALL, Carla Merkle. **Cloud Telescope: An Ephemeral, Distributed, and Cloud-Native Architecture for Collecting Internet Background Radiation**. IEEE Access, v. 13, p. 45682-45714, 2025.

IRWIN, Barry V. W. **A framework for the application of network telescope sensors in a global IP network**. 2011. Tese (Doutorado em Ciência da Computação) – Department of Computer Science, Rhodes University, Makhanda, South Africa, 2011.

MOORE, David et al. **Network telescopes: Technical report**. San Diego: Cooperative Association for Internet Data Analysis (CAIDA), University of California, 2004. (Technical Report tr-2004-04).

PANG, Ruoming et al. Characteristics of internet background radiation. In: ACM SIGCOMM CONFERENCE ON INTERNET MEASUREMENT (IMC), 4., 2004, Taormina. **Proceedings [...]**. New York: ACM, 2004. p. 27-40.

RICHTER, Philipp et al. A primer on IPv4 scarcity. **ACM SIGCOMM Computer Communication Review**, v. 45, n. 2, p. 21-31, abr. 2015.

SHAIKH, F. et al. Internet of Malicious Things: Correlating active and passive measurements for inferring and characterizing Internet-scale unsolicited IoT devices. **IEEE Communications Magazine**, v. 56, n. 9, p. 170-177, set. 2018.

SHODAN. **Account Billing**. [s.l.], 2026. Disponível em: https://account.shodan.io/billing. Acesso em: 30 jun. 2026.

TUNDIS, Andrea; NGA, Eric Marc Modo; MÜHLHÄUSER, Max. An exploratory analysis on the impact of Shodan scanning tool on the network attacks. In: INTERNATIONAL CONFERENCE ON AVAILABILITY, RELIABILITY AND SECURITY (ARES), 16., 2021, Vienna. **Proceedings [...]**. New York: ACM, 2021. p. 1-10.

WAZLAWICK, Raul Sidnei. **Metodologia de pesquisa para ciência da computação**. 3. ed. Rio de Janeiro: LTC, 2021.

WUSTROW, Eric et al. Internet background radiation revisited. In: ACM SIGCOMM CONFERENCE ON INTERNET MEASUREMENT (IMC), 10., 2010, Melbourne. **Proceedings [...]**. New York: ACM, 2010. p. 62-74.

ZAKROUM, Mohammed et al. Monitoring network telescopes and inferring anomalous traffic through the prediction of probing rates. **IEEE Transactions on Network and Service Management**, v. 19, n. 4, p. 5170-5182, dez. 2022.
