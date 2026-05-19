# SecureWiki CTF

https://github.com/mar-01/securewiki-ctf.git
Vagrant + Ansible Provisioning für die SecureWiki Challenge.

## Build

    vagrant up

## Verbinden

- Web: http://192.168.56.110/dokuwiki/
- SSH (Vagrant-User): vagrant ssh
- SSH (Challenge-User): ssh jhartmann@192.168.56.110

## Rebuild

    vagrant destroy -f && vagrant up

## Szenario

    Die Hartmann & Partner Rechtsanwälte, eine Kanzlei mit fünf Mitarbeitern, betreibt ein internes Wiki für Fallnotizen und Mandantenkontakte. Der Server securewiki.hartmann-legal.local (Ubuntu 22.04) wurde 2018 vom damaligen IT-affinen Schwiegersohn der Seniorpartnerin als DokuWiki-Instanz aufgesetzt; dieser hatte sich das runcommand-Plugin für ein nie zu Ende geführtes Skript-Frontend installiert. 2023 übergab die Kanzlei die Wartung an einen externen IT-Dienstleister, der nichts an Versionen änderte ("läuft ja"). Der Dienstleister verließ die Kanzlei Anfang 2025; seitdem patcht niemand mehr. Eine Paralegal mit SSH-Zugang (jhartmann) hatte vor Monaten um einen schnellen Backup-Helfer gebeten, den der Admin per sudo NOPASSWD "mal eben" freigegeben hat. Der Spieler ist externer Penetration Tester im Auftrag des neu eingestellten Datenschutzbeauftragten und soll nachweisen, dass vertrauliche Mandantenakten kompromittierbar sind.
