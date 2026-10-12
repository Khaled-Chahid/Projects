# Guide d'exécution – AWS Cloud Risk Tool

## Prérequis

Avant de lancer le projet :

* Docker Desktop doit être installé et démarré ;
* Python doit être installé ;
* PowerShell doit être disponible.

## 1. Ouvrir PowerShell

Ouvrir PowerShell dans le dossier racine du projet.

Autoriser temporairement l'exécution des scripts :

```powershell
Set-ExecutionPolicy -Scope Process Bypass
```

Cette modification concerne uniquement la session PowerShell actuelle.

## 2. Créer le laboratoire et lancer le scan

Exécuter :

```powershell
.\scripts\quickstart.ps1
```

Cette commande :

* démarre LocalStack sur Docker ;
* crée le laboratoire AWS fictif ;
* lance le scan ;
* génère les résultats.

## 3. Ouvrir le rapport

```powershell
Start-Process .\output\report.html
```

## Relancer uniquement le scan

Pour effectuer un nouveau scan sans reconstruire le laboratoire :

```powershell
.\scripts\scan-localstack.ps1
```

## Réinitialiser le laboratoire

Pour supprimer le laboratoire actuel et le reconstruire depuis zéro :

```powershell
.\scripts\reset-lab.ps1
```

## Arrêter le laboratoire

Après utilisation :

```powershell
.\scripts\stop-lab.ps1
```

## Architecture d'exécution

```text
Docker Desktop
      ↓
LocalStack : localhost:4566
      ↓
Laboratoire AWS fictif
      ↓
Scan Python
      ↓
Rapport HTML
```
