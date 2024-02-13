# Proxmox

## Out Of Range Error

- [test](https://robertoviola.cloud/2020/04/16/proxmox-no-screen-during-installation/)

## IMPORT Paloalto QCOW2

- [test](https://ostechnix.com/import-qcow2-into-proxmox/)


## Host Key Changes

- if you get the following:

- Do the following:

   53  ssh-keygen -f "/etc/ssh/ssh_known_hosts" -R "HOST IP ADDRESS"
   54  ssh-keygen -f "/etc/ssh/ssh_known_hosts" -R "HOST NAME"
   55  /usr/bin/ssh -e none -o 'HostKeyAlias="HOST  NAME"' root@"HOST IP ADDRESS" /bin/true