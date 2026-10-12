# Audit de configuration et durcissement d’un serveur web Apache

Projet académique consacré à l’audit de la configuration de sécurité d’un serveur web Apache et à son durcissement dans un environnement virtualisé local.

La démarche consiste à établir un état initial, analyser les risques, appliquer des mesures de sécurisation, puis vérifier leur efficacité par une comparaison avant/après.

## Environnement et outils

- **Environnement :** VMware, Kali Linux, Apache, PHP et MariaDB. DVWA est déployée comme application de laboratoire.
- **Outils d’audit :** Nmap, Nikto, WhatWeb, curl et OpenSSL.
- **Mesures de durcissement :** pare-feu UFW, configuration SSH, permissions des fichiers, configuration Apache et HTTPS/TLS.

## Plan du projet

1. **Phase 1 :** Mise en place de l’environnement de travail
2. **Phase 2 :** Audit de sécurité initial
3. **Phase 3 :** Analyse des résultats et évaluation des risques
4. **Phase 4 :** Durcissement du système d’exploitation
5. **Phase 5 :** Durcissement du serveur web Apache
6. **Phase 6 :** Sécurisation des communications (HTTPS / TLS)
7. **Phase 7 :** Audit post-durcissement et vérification finale

## Rapport

Le rapport détaille les étapes réalisées, les configurations appliquées et les vérifications effectuées. Le périmètre porte sur la sécurité du système et du serveur web ; les tests d’intrusion applicatifs approfondis de DVWA ne sont pas inclus.
