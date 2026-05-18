# SecureWiki CTF

Vagrant + Ansible Provisioning für die SecureWiki Challenge.

## Build

    vagrant up

## Verbinden

- Web: http://192.168.56.110/dokuwiki/
- SSH (Vagrant-User): vagrant ssh
- SSH (Challenge-User): ssh jhartmann@192.168.56.110

## Rebuild

    vagrant destroy -f && vagrant up
