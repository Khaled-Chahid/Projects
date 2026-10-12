# Cloud Risk Tool – Azure

## Présentation

Ce projet consiste à développer un outil de découverte, d'analyse et de scoring des risques de sécurité dans un environnement cloud Azure fictif.

## Sujet

**Développement d'un outil de découverte et de scoring de risque sur un environnement cloud fictif (AWS/Azure), avec détection des :**

* mauvaises configurations IAM / RBAC ;
* stockages exposés ;
* assets orphelins.

Cette version concerne la partie **Azure**.

## Fonctionnement

Le projet suit le pipeline suivant :

```text
Discovery → Analysis → Scoring → Reporting
```

* **Discovery** : collecte les ressources et configurations Azure.
* **Analysis** : détecte les mauvaises configurations et risques.
* **Scoring** : calcule le niveau de criticité des findings.
* **Reporting** : génère le rapport final.

Les principales catégories analysées sont :

* RBAC et identités ;
* Storage ;
* Compute ;
* Network ;
* Resources.

## Environnement de test

Le projet utilise **Topaz** afin de disposer d'un environnement Azure fictif sans utiliser un abonnement Azure réel.

Topaz fonctionne localement dans un conteneur **Docker** et expose une API compatible avec les besoins du projet.

L'endpoint principal utilisé est :

```text
https://topaz.local.dev:8899
```

Le port principal est donc :

```text
8899
```

Le fonctionnement général est :

```text
Docker
   ↓
Topaz
   ↓
Azure-like API locale
   ↓
Laboratoire Azure fictif
   ↓
Code Python
   ↓
Discovery
   ↓
Analysis
   ↓
Scoring
   ↓
Reporting
```

Le laboratoire contient des ressources volontairement configurées de manière à permettre la détection des risques attendus.

## Technologies utilisées

* Python
* Docker
* Docker Compose
* Topaz
* PowerShell
* Azure-like REST API

## Structure du projet

```text
azure-risk-tool
|   pyproject.toml
|
+---scripts
|       quickstart.ps1
|       reset-lab.ps1
|       scan-topaz.ps1
|       start-lab.ps1
|       stop-lab.ps1
|
+---src
|   \---azure_risk_tool
|       |   azure.py
|       |   cli.py
|       |   config.py
|       |   lab.py
|       |   pipeline.py
|       |   serialization.py
|       |   __init__.py
|       |   __main__.py
|       |
|       +---analysis
|       |       common.py
|       |       manager.py
|       |       network.py
|       |       orphan.py
|       |       rbac.py
|       |       storage.py
|       |       __init__.py
|       |
|       +---discovery
|       |       common.py
|       |       compute.py
|       |       identity.py
|       |       manager.py
|       |       network.py
|       |       rbac.py
|       |       resources.py
|       |       storage.py
|       |       __init__.py
|       |
|       +---reporting
|       |       generator.py
|       |       __init__.py
|       |
|       \---scoring
|               engine.py
|               __init__.py
|
\---topaz
        compose.yml
        Dockerfile
        init-azure.py
        init-azure.sh
```

Les principaux répertoires sont :

* `discovery/` : collecte des ressources et configurations Azure ;
* `analysis/` : détection des mauvaises configurations RBAC, problèmes Storage, Network et assets orphelins ;
* `scoring/` : calcul du niveau de risque ;
* `reporting/` : génération du rapport ;
* `topaz/` : configuration et initialisation du laboratoire Azure fictif ;
* `scripts/` : scripts permettant de démarrer, scanner, réinitialiser et arrêter le laboratoire.

## Résultat

Après le scan, le rapport principal est généré dans :

```text
output/report.html
```
