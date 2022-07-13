# Introdução

A room aborta algumas técnicas sobre elevação de privilégios em ambientes Linux. A partir de um VM Debian propositalmente vulnerável, é possível praticar tais técnicas.

# Execução

## 1 - Deploy the Vulnerable Debian VM

Primeira task consiste basicamente em realizar o deploy (iniciar) a VM. São repassadas informações de acesso SSH: usuário -> **user**; senha -> **password321**

### Questões:

- a. ***Deploy the machine and login to the "user" account using SSH***: *Não há necessidade de resposta*

- b. ***Run the "id" command. What is the result?*** *uid=1000(user) gid=1000(user) groups=1000(user),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev)*
