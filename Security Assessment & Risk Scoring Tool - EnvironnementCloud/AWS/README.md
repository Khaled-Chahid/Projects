# Cloud Risk Tool – AWS

## Présentation

Ce projet consiste à développer un outil de découverte, d'analyse et de scoring des risques de sécurité dans un environnement cloud AWS fictif.

## Sujet

**Développement d'un outil de découverte et de scoring de risque sur un environnement cloud fictif (AWS/Azure), avec détection des :**

* mauvaises configurations IAM ;
* buckets exposés ;
* assets orphelins.

Cette version concerne la partie **AWS**.

## Fonctionnement

Le projet suit le pipeline suivant :

```text
Discovery → Analysis → Scoring → Reporting
```

* **Discovery** : collecte les informations sur les ressources AWS.
* **Analysis** : recherche les mauvaises configurations et risques.
* **Scoring** : attribue un niveau de risque aux findings détectés.
* **Reporting** : génère les résultats et le rapport final.

Les principales ressources analysées sont :

* IAM ;
* Amazon S3 ;
* Amazon EC2.

## Environnement de test

Le projet utilise **LocalStack** afin de disposer d'un environnement AWS fictif sans utiliser un compte AWS réel.

LocalStack fonctionne localement dans un conteneur **Docker** et simule les services AWS nécessaires au projet.

Son endpoint principal est :

```text
http://localhost:4566
```

Le port `4566` est utilisé par le code Python pour communiquer avec les services AWS simulés.

Le fonctionnement général est :

```text
Docker Desktop
      ↓
LocalStack
      ↓
IAM / S3 / EC2 simulés
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
* boto3
* Docker
* Docker Compose
* LocalStack
* PowerShell

## Structure du projet

```text
\---cloud-risk-tool
    |   pyproject.toml
    |
    +---localstack
    |       compose.yml
    |       Dockerfile
    |       init-aws.sh
    |
    +---scripts
    |       quickstart.ps1
    |       reset-lab.ps1
    |       scan-localstack.ps1
    |       start-lab.ps1
    |       stop-lab.ps1
    |
    \---src
        \---cloud_risk_tool
            |   aws.py
            |   cli.py
            |   config.py
            |   pipeline.py
            |   serialization.py
            |   __init__.py
            |   __main__.py
            |
            +---analysis
            |       common.py
            |       iam.py
            |       manager.py
            |       orphan.py
            |       s3.py
            |       __init__.py
            |
            +---discovery
            |       ec2.py
            |       iam.py
            |       manager.py
            |       s3.py
            |       __init__.py
            |
            +---reporting
            |       generator.py
            |       __init__.py
            |
            \---scoring
                    engine.py
                    __init__.py
```

Les répertoires principaux sont :

* `discovery/` : découverte des ressources IAM, S3 et EC2 ;
* `analysis/` : détection des mauvaises configurations IAM, buckets exposés et assets orphelins ;
* `scoring/` : calcul du niveau de risque ;
* `reporting/` : génération du rapport ;
* `localstack/` : configuration du laboratoire AWS fictif ;
* `scripts/` : scripts permettant de démarrer, scanner, réinitialiser et arrêter le laboratoire.

## Résultat

Après le scan, le rapport principal est généré dans :

```text
output/report.html
```
