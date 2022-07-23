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

## Task 4 - Collection Methods  

Existem algumas maneiras de se reunir um arquivo PCAP. Coletar o tréfego e trazer para o Wireshark envolve algumas técnicas: tap, port mirroring, MAC floods, ARP Poisoning. É possível configurar as técnicas em uma live capturing do Wireshark.

### Visão geral dos métodos de coleta

Algumas coisas antes de tentar coletar e monitorar capturas com live capturing:

- Comece com uma captura de amostra para garantir que tudo esteja configurado corretamente e que você esteja capturando o tráfego com sucesso.

- Certifique-se de ter poder computacional suficiente para lidar com o número de pacotes com base no tamanho da rede, isso obviamente variará de rede para rede.

- Garanta espaço em disco suficiente para armazenar todas as capturas de pacotes.

Depois de atender a todos esses critérios e escolher um método de coleta, você pode começar a monitorar e coletar ativamente os pacotes em uma rede.

### Network taps

Consiste em uma implantação física, em que se "toca" (grampo) fisicamente em um cabo de transmissão de dados. Essa técnica é comumente utilizada por times de Threat Hunting/DFIR e Red Teams, objetivando sniff e captura de pacotes.

Existem dois meios principais de grampear um fio. A primeira é usando hardware para grampear o fio e interceptar o tráfego à medida que ele passa, um exemplo disso seria um grampeador de vampiro, conforme ilustrado abaixo.

![Grampo](images/tap.gif)

Outra opção para plantar um tap de rede seria um tap de rede inline, que você plantaria entre ou 'inline' dois dispositivos de rede. O tap irá replicar os pacotes conforme eles passam pelo tap. Um exemplo deste toque seria o muito comum Throwing Star LAN Tap.

![Grampo inline](images/tap2.jpg)

### Mac Floods

MAC Floods é uma tática muito utilizada por Red Teams como forma de sniffing ativo de pacotes. O MAC Flooding destina-se a estressar o switch e preencher a tabela CAM. Assim que a tabela CAM estiver preenchida, o switch não aceitará mais novos endereços MAC e, portanto, para manter a rede ativa, o switch enviará pacotes para todas as portas do switch.

***Nota***: Esta técnica deve ser usada com extrema cautela e com consentimento prévio explícito do contratante de um pentest.

### ARP Poisoning

ARP Poisoning é outra técnica usada por Red Teams para sniffing ativo de pacotes. Por ARP Poisoning você pode redirecionar o tráfego do(s) host(s) para a máquina da qual você está monitorando. Essa técnica não sobrecarregará equipamentos de rede como MAC Flooding, mas ainda deve ser usada com cautela e somente se outras técnicas, como taps de rede, não estiverem disponíveis.

### Questões:

- a. ***Read the above and practice collecting captures, as well as understand the various capture techniques available.*** *Não há necessidade de resposta*

## Task 5 - Filtering Captures 

Aplicar filtros de pacotes é muito importante, sobretudo quando se tem uma captura muito grande com mais de 100.000 pacotes. Na Task 3,foi mostrado como configurar filtro antes de iniciar uma captura. Existe uma segunda forma que é conhecido como filtros de exibição, em que se pode aplicar filtros de exibição de duas maneiras: através da guia analisar e na barra de filtros na parte superior da captura de pacotes.

### Operadores de filtro

Existe uma sintaxe bem simples no Wireshark para utilização em filtros. Abaixo os operadores:

- **and**: *and* / *&&*
- **or**: *or* / *||*
- **equals**: *eq* / *==*
- **not equal**: *ne* / *!=*
- **greater than**: *gt* / *>*
- **less than**: *lt* / *<*

Existem outros operadores que podem ser utilizados no wireshark, mais informações [aqui](https://www.wireshark.org/docs/wsug_html_chunked/ChWorkBuildDisplayFilterSection.html).

### Filtro Básico

Pode-se filtrar as informações de uma captura ou uma arquivo PCAP por IP ou protocolo, dentre outras informações.

***Filtro por IP***: permitirá que se vasculhe o tráfego e veja apenas os pacotes com um endereço IP específico contido nesses pacotes, seja da origem ou do destino.

***Sintaxe***: ip.addr == \<IP Address\>

![Filtro por IP](images/filter_by_ip.png)

***Filtro por protocolo TCP***: É possível filtrar por uma porta ou protocolo. Com o Wireshark é possível filtrar tanto por número de porta como por nome de protocolo.

***Sintaxe***: tcp.port eq \<Port #\> or \<Protocol Name\>

![Filtro por porta e protocolo](images/filter_by_port_protocol.png)

***Filtro por protocolo UPD***: Também é possível filtrar por UDP, bastando mudar o prefixo de TCP para UDP.

***Sintaxe***: udp.port eq \<Port #\> or \<Protocol Name\>

### Questões:

- a. ***Read the above and understand the basics of packet filtering.*** *Não há necessidade de resposta*

## Task 6 - Packet Dissection 

O Wireshark usa a arquitetura OSI para dividir os pacotes. Conhecimento na arquitetura OSI de 7 camadas é importante.

![Arquitetura OSI](images/OSI-7Layers.png)

### Detalhes do pacote

Para exibir detalhes de um pacote capturado, basta um duplo clique nele.

Os pacotes consistem em 5 a 7 camadas com base no modelo OSI. Para ilustrar, serão analisados todos eles em um pacote HTTP de uma captura de amostra.

![Detalhes de um pacote HTTP](images/details01.png)

De acordo com a figura acima, pode-se ver as 7 camadas distintas para o pacote: frame/packet, source [MAC], source [IP], protocolo, erros de protocolo, protocolo de aplicação e dados de aplicação. Abaixo, figura com as camadas com mais detalhes.

- ***Frame (Layer 1)***: Exibe qual quadro/pacote está visualizando, bem como detalhes específicos da camada física do modelo OSI.

![Frame Layer 1](images/details02.png)

- ***Source [MAC] (Layer 2)***: Exibe os endereços MAC de origem e destino. Relacionado à camada de enlace de dados do modelo OSI.

![Frame Layer 2](images/details03.png)

- ***Source [IP] (Layer 3)***: Exibe os endereços IPv4 de origem e destino. Relaciona à camada de rede do modelo OSI.

![Frame Layer 3](images/details04.png)

- ***Protocol (Layer 4)***: Exibe detalhes do protocolo usado (UDP/TCP) junto com as portas de origem e destino. Relacionado à camada de transporte do modelo OSI.

![Frame Layer 4](images/details05.png)

- ***Protocol Errors***: Esta é uma continuação da 4ª camada mostrando segmentos específicos do TCP que precisavam ser remontados.

![Erros de protocolo camada 4](images/details06.png)


- ***Application Protocol (Layer 5)***: Exibe detalhes específicos do protocolo que está sendo usado, como HTTP, FTP, SMB, etc. Relacionado à camada de aplicação do modelo OSI.

![Camada de aplicação](images/details07.png)

- ***Application Data***: Esta é uma extensão da camada 5 que pode mostrar os dados específicos do aplicativo.

![Extensão da camada de aplicação](images/details08.png)

Nota: Mesmo sendo citado o modelo OSI, no texto da task, ficou evidente estar sendo abordado o modelo de camadas TCP/IP.

### Questões:

- a. ***Read the above and move on to analyzing application protocols.*** *Não há necessidade de resposta*

## Task 7 - ARP Traffic

### Visão geral - ARP

ARP (Address Resolution Protocol) é um protocolo da camada 2 que é usado conectar um endereço IP a um endereço MAC, faz um de - para. Esse protocolo possui duas mensagens de interesse nesse momento: REQUEST e REPLY. Uma maneira de identificar em pacotes capturados, consiste verificar     no cabeçalho da mensagem, que pode conter *operation codes*:

- Request (1)
- Reply (2)

Abaixo, você pode ver uma captura de pacote de várias solicitações e respostas ARP:

![ARP Request - Replies](images/arp01.png)

É importante observar que a maioria dos dispositivos se identificará ou o Wireshark o identificará como Intel_78, um exemplo de tráfego suspeito seria muitas solicitações de uma fonte não reconhecida. No entanto, pode-se habilitar uma configuração no Wireshark para resolver endereços físicos. Para habilitar esse recurso, navegue até *View > Name Resolution >* Certifique-se de que *Resolve Physical Addresses* esteja marcado.

Observando a captura de tela abaixo, podemos ver que um dispositivo Cisco está enviando solicitações ARP, o que significa que devemos confiar nesse dispositivo, no entanto, deve-se sempre ter cautela ao analisar pacotes.

![Pacotes ARP do mesmo dispositivo](images/arp02.png)

### Trafégo ARP

- ***Pacotes ARP Request***: Pode-se começar a analisar os pacotes examinando o primeiro pacote de solicitação ARP e os detalhes do pacote.

![Arp request](images/arp03.png)

Observando os detalhes do pacote acima, os detalhes mais importantes do pacote estão destacados em vermelho. O Opcode é a abreviação de código de operação e você informará se é uma REQUEST ou REPLY ARP. O segundo detalhe descrito é para onde o pacote está solicitando, neste caso, está transmitindo o pedido para todos.

- ***Pacotes ARP Reply***: 

![Arp reply](images/arp04.png)

Observando os detalhes do pacote acima, podemos ver no Opcode que é um pacote ARP Reply. Também podemos obter outras informações úteis, como o endereço MAC e IP que foi enviado junto com a resposta, pois este é um pacote de resposta, sabemos que essa foi a informação enviada junto com a mensagem.

O ARP é um dos protocolos mais simples de se analisar, tudo o que se precisa lembrar é identificar se é um pacote de solicitação ou resposta e por quem está sendo enviado.

### Laboratório prático

Para ilustrar será utilizado o arquivo pcap [nb6-startup.pcap](nb6-startup.pcap).

Para carregar o arquivo no wireshark, basta clicar no menu File->Open.

Após abrir, responder as questões.

### Questões:

- a. ***What is the Opcode for Packet 6?*** *request (1)* 

- b. ***What is the source MAC Address of Packet 19?*** *80:fb:06:f0:45:d7*

- c. ***What 4 packets are Reply packets?*** *76,400,459,520*

Para responder a questão ***c***, coloca-se no filtro: arp. Em seguida, no resultado, procura-se por opcodes de replies.

- d. ***What IP Address is at 80:fb:06:f0:45:d7?*** *10.251.23.1*

Para responder a questão ***d***, coloca-se no filtro: eth.addr == 80:fb:06:f0:45:d7 and arp. Em seguida, no resultado, procura-se por reply com esse mac.

## Task 8 - ICMP Traffic

### ICMP - visão geral

O ICMP (Internet Control Message Protocol) é utilizado para analisar nodes em uma redes. É comumente utilizado no utilitário de linha de comando ***ping***. Mais detalhes sobre o ICMP na [RFC792](https://datatracker.ietf.org/doc/html/rfc792).

Na imagem abaixo, pode-se observar como pacotes ICMP aparecem no wireshark. Há um request e um reply.

![ICMP request e reply](images/icmp01.png)

### Visão do tráfego ICMP

- ***ICMP Request***: Na imagem mais abaixou, pode-se perceber detalhes de um ping request. Algumas coisas importantes a se notar nos detalhes do pacote, dentre elas o tipo e código.

Um tipo igual a 8 é um pacote de request. Um tipo igual a 0 é um pacote de reply. Quando esses códigos são alterados ou não parecem corretos, isso geralmente é um sinal de atividade suspeita.

Há dois outros detalhes dentro do pacote que são úteis para analisar: timestamp e data. O timestamp de data/hora pode ser útil para identificar a hora em que o ping foi solicitado, também pode ser útil para identificar atividades suspeitas em alguns casos. Também podemos olhar para a string de dados que normalmente será apenas uma string de dados aleatória.

![ICMP - Request](images/icmp02.png)

- ***ICMP Reply***: Na imagem mais abaixo, pode-se perceber que o pacote de reply é similar ao de request. A principal diferença que distingue-o do resquest é o código do tipo, no caso do reply, é o 0.

Observe a imagem abaixo para perceber a diferença:

![ICMP - Reply](images/icmp03.png)

### Laboratório prático

Para responder as questões, basta carregar no wireshark o arquivo [dns_icmp.pcapng](dns_icmp.pcapng). Nele só há dois protocolos, aplique um filtro por icmp.

![ICMP Filtro](images/icmp04.gif)

Os pacotes são numerados no wireshark, o que facilita para identificação e responder às questões.
### Questões:

- a. ***What is the type for packet 4?*** *8*

Sobre a questão ***a***, o pacote 4 é um ICMP request, ou seja, 8.

- b. ***What is the type for packet 5?*** *0*

- c. ***What is the timestamp for packet 12, only including month day and year?*** *May 30, 2013*

Para responder a questão ***c***, basta um clique no pacote 12 e inspecionar os detalhes.

![ICMP detalhes - timestamp](images/icmp05.png)

- d. ***What is the full data string for packet 18?*** *08090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637*

Para responder a questão ***d***, basta clicar no pacote 18 e em detalhes localizar o campo ***Data***. Pode-se copiar o valor clicando como botão direito.

![Copia do data](images/icmp06.gif)


## Task 9 - TCP Traffic 

### TCP - Visão Geral

O TCP (Transmission Control Protocol) trabalha com a entrega de pacotes, incluindo sequenciamento e tratamento de erros. Para mais detalhes, acessar a [RFC 793](https://datatracker.ietf.org/doc/html/rfc793).

Na imagem abaixo, é possível perceber um exemplo com nmap scan, nas portas 80 e 443. Percebe-se que as portas estão fechadas em virtude dos pacotes com RST e ACK em vermelho.

![TCP 01](images/tcp01.png)

Ao analisar pacotes TCP, o Wireshark pode ser muito útil, pois codifica por cores os pacotes em ordem de nível de perigo. 

O TCP pode fornecer informações úteis sobre uma rede ao analisar, mas também pode ser difícil de analisar devido ao número de pacotes que ele envia. É aqui que você pode precisar usar outras ferramentas como RSA NetWitness e NetworkMiner para filtrar e analisar melhor as capturas.

### Visão geral do tráfego TCP

O mais comum de se observar ao analisar um tráfego TCP é o que se chama de Handshake TCP. O handshake inclui uma série de pacotes com determinadas flags: syn, synack, ack. São usadas para estabelecer uma comunicação.

![Handshake](images/tcp02.png)

Normalmente, quando esse handshake está fora de ordem ou quando inclui outros pacotes, como um pacote RST, algo suspeito ou errado está acontecendo na rede. A varredura do Nmap na seção acima é um exemplo perfeito disso.

### Análise de pacotes TCP

Para analisar pacotes TCP no wireshark, é preciso ir nos detalhes de cada pacote. Pode-se observar alguns comportamentos e estruturas que os pacotes possuem.

Na imagem abaixo, detalhes de um pacote com a flag SYN. A principal coisa que se procura ao olhar para um pacote TCP é o número de sequência e o número de confirmação.

![TCP SYN detalhes](images/tcp03.png)

Nesse caso, vemos que a porta não estava aberta porque o número de confirmação é 0.

No Wireshark, também podemos ver o número de sequência original navegando para editar > preferências > protocolos > TCP > números de sequência relativos (desmarque a caixa).

![Config do wireshark](images/tcp04.png)

![TCP Análise](images/tcp05.png)

Normalmente, os pacotes TCP precisam ser vistos como um todo para contar uma história, em vez de um por um nos detalhes.

### Questões:

- a. ***Read the above and move into Task 10.*** Não há necessidade de resposta