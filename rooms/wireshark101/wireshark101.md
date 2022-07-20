# Introdução

A room oferece oportunidade de aprendizado sobre o básico do Wireshark e como analisar vários protocolos e PCAPs.

# Execução

## Task 1 - Introduction

O Wireshark é uma ferramenta usada para criar e analisar PCAPs (arquivos de captura de pacotes de rede). É uma das melhores ferramentas de análise de pacotes. 

Nesta room, serão abordados os fundamentos da instalação do Wireshark e seu uso para realizar a análise básica de pacotes e examinar detalhadamente cada protocolo de rede comum.

![Wireshark](images/wireshark101-01.png)

### Questões:

- a. ***Informações*** *Não há necessidade de resposta*

## Task 2 - Installation

A instalação do wireshark é bem simples. Mais informações no [link](https://www.wireshark.org/download.html).

Na maioria das distribuições Linux já existe no repositório de pacotes para instalação, bastando utilizar o gerenciador pacotes para instalar (apt, yum, dnf, etc).

### Questões:

- a. ***Read the above, and ensure you have Wireshark installed.*** *Não há necessidade de resposta*

## Task 3 - Wireshark Overview 

A primeira tela ao abrir o wireshark mostra opções sobre seleção de interface, filtros:

![Tele inicial](images/wireshark101-02.png)

Na imagem, existem várias interfaces. Isso varia de acordo com o computador. É possível também iniciar uma *Live Capture* em uma interface ou carregar um arquivo PCAP.

É importante perceber os gráficos de atividades ao lado de cada interface. Isso indica que uma interface está com tráfego. Capturar em uma interface que não tem atividade, pode ser inútil.

### Live Capture

No topo da lista de interfaces, na bandeirinha verde, é possível escolher uma série de filtros para facilitar o trabalho:

![Filtros](images/wireshark101-filters01.gif)

Não é obrigatório selecionar um filtro, mas isso ajuda a melhor organizar o que será mostrado na captura.

Uma vez que você selecionou a interface e filtros, basta clicar em iniciar captura:

![Iniciar captura](images/wireshark101-start_capture_01.gif)

Quando precisar parar a captura, basta clicar no botão Stop (Vermelho) na barra de ferramentas do topo.

### Arquivo PCAP

Caso tenha um arquivo PCAP e queira analisar, basta clicar no menu File->Open e selecionar o arquivo.

### Informações da tela de captura

Tanto quando se faz uma live capture ou se carrega um arquivo PCAP, a tela exibe uma série de informações:

- Packet Number
- Time
- Source
- Destination
- Protocol
- Length
- Packet Info

Juntamente com informações rápidas de pacotes, o Wireshark também codifica pacotes por cores em ordem de nível de perigo, bem como protocolo para poder detectar rapidamente anomalias e protocolos nas capturas.

![Anomalias](images/wireshark101-03.png)

As informações são úteis, dependendo da necessidade.

### Questões:

- a. ***Read the above and play around with Wireshark.*** *Não há necessidade de resposta*