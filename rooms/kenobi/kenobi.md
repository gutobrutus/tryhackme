# Introdução

Passo a passo sobre como explorar uma máquina Linux. Enumere o Samba para compartilhamentos, manipule uma versão vulnerável do proftpd e amplie seus privilégios com manipulação de variável PATH.

# Execução

### Task 1 - Portscan inicial

Antes de executar o nmap:

```shell
export TARGET=IP_DO_ALVO
```

Execução do nmap:

```shell
┌──(root㉿kali)-[/tryhackme/rooms/kenobi]
└─# nmap -A -T5 -Pn -p- $TARGET -oA portscan -vvv
```
### Questões:

- a. ***Make sure you're connected to our network and deploy the machine*** *Não há necessidade de resposta*

- b. ***Scan the machine with nmap, how many ports are open?*** *7*
