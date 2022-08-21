# Intro to ISAC

Nesta room será ensinado como utilizar o compartilahmento de informações e análises de centros especializados sobre inteligência de ameaças e IOCs (Indicators of Compromise).

## Task 1 - Introduction

Information Sharing and Analysis Centers (ISACs) são utilizados para compartilhar e trocar vários IOCs (Indicators of Compromise), objetivando ter inteligência de ameaças (Threat Intelligence). Os IOCs podem conter MD5s, IPs, Yara Rules, dentre outros. Existe uma série de ISACs que podem ser utilizados, como: AlienVault OTX, Threat Connect e o MISP (Malware Information Sharing Platform).

![Logo inicial](images/logoInit.png)

Malwares e IOCs que foram utilizados nesta room são providos por [The Zoo Malware Repository](https://github.com/ytisf/theZoo).

**Atenção**: Esta room usa malware neutralizados em um ambiente virtual, tenha cuidado ao interagir com amostras.

### Questões:

- a. ***Read the above and move on to 'What are ISACs'.*** *Não há necessidade de resposta*

## Task 2 - Basic Terminology

Antes de nos aprofundar no tema ISACs, é necessário uma dicussão prévia sobre alguns termos como frameworks, threat intelligence, etc.

**APT** é um acrônico para ***Advanced Persistent Threat***. São considerados um time/grupo (***threat group***) ou mesmo um país/nação (nation-state group) que atuam ou se dedicam/envolvem em ataques de longo prazo contra organizações e/ou países.

O termo "***Advanced***" pode causar uma interpretação equivocada, pois pode passar a ideia que cada grupo APT possui uma super arma, como por exemplo, um zero-day exploit, que eles podem utilizar em seus ataques. Este não é o caso, pois as técnicas que tais grupos de APT usam são bastante comuns e podem ser detectadas com as aplicações corretas. [Aqui](https://www.fireeye.com/current-threats/apt-groups.html) pode ser consultada uma lista de grupos APT da FireEye.

**TTP** é um acrônimo para ***Tactics, Techiniques e Procedures***. Abaixo o que cadda um dos termos é:

- ***Tactic*** é uma meta ou objetivo de um adversário.
- ***Techinique*** é como um adversário alcança uma determinada meta ou objetivo.
- ***Procedure*** é como uma determinada técnica é executada.

**TI** é um acrônico para ***Threat Intelligence*** (Inteligência sobre Ameaças). Threat Intelligence é um termo que abrange todas as inforamações coletadas sobre os adversários e TTPs. Outra nomeclatura sinônima que pode ser encontrada é **CTI** ou ***Cyber Threat Intelligence***.

**IOCs** é um acrônico para ***Indicators of Compromise***, indicadores para malwares ou grupos APT. Esses indicadores podem ser uma hash de arquivos, IPs, nomes, etc.

**Nota**: O termos adversários é um sinônimo para atacante, invasor.

### Questões:

- a. ***Read the above and familiarize yourself with the various terminology.*** *Não há necessidade de resposta*

## Task 3 - What is Threat Intelligence

Threat Intelligence, também conhecido como TI ou Cyber Threat Intelligence (CTI), é utilizado para prover/buscar informações sobre o cenário de ameaças de adversários específicos e seus TTPs.

Somente os dados analisados devem ser enquadrados como Threat Intelligence. Uma vez analisados, tornam-se inteligência sobre ameaças. Outro detalhe, é que os dados precisam de um contexto para se tornarem informações.

CTI é uma medida de prevenção que companhias/empresas/organizações usam ou contribuem para que outras companhias não sofram os mesmos ataques. É claro que os adversários/atacantes mudam seus TTPs o tempo todo. Portanto, o cenário de Threat Intelligence é bastante dinâmico, muda constantemente.

Fornecedores e corporações, às vezes, fornecem seus CTIs coletados no que chamamos de ISACs ou, em tradução direta, Centros de Compartilhamento e Análise de Informações. Os ISACs coletam vários indicadores de um adversário que outras corporações podem usar como precaução contra atacantes.

Caso não se tenha familiriadade com atacantes/adversários e seus TTPs, pode-se consultar a room [Mitre](https://tryhackme.com/room/mitre). Outras duas fontes de informações são:

- [APT Groups and Operations](https://apt.threattracking.com/)
- [FireEye APT Report](https://www.fireeye.com/current-threats/apt-groups.html).

Threat Intelligence pode ser subdividida em três diferentes tipos:

- ***Strategic***: auxilia/ajuda a alta gerência a tomar decisões especificamente sobre o orçamento e as estratégias de segurança.
- ***Tactical***: Interage com os TTPs e modelos de ataques para identificar padrões de tais ataques.
- ***Operational***: Interage com os IOCs e como os adversários operam.

O foco principal desta room é o tipo operacional.

### Questões:

- a.  ***Read the above and move on to, What are ISACs*** *Não há necessidade de resposta*

