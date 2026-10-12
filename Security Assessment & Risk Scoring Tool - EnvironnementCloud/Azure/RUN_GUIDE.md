# Guide d'exécution – Azure Cloud Risk Tool

## Prérequis

Avant de lancer le projet :

* Docker Desktop doit être installé et démarré ;
* Python doit être installé ;
* PowerShell doit être disponible.

## 1. Configurer l'accès réseau local

Cette étape est nécessaire avant la première utilisation.

Ouvrir **PowerShell en tant qu'administrateur**, puis ajouter l'entrée suivante dans le fichier `hosts` :

```powershell
Add-Content -Path "$env:SystemRoot\System32\drivers\etc\hosts" -Value "`n127.0.0.1 topaz.local.dev"
```

Vider ensuite le cache DNS :

```powershell
ipconfig /flushdns
```

Vérifier que le nom est correctement résolu :

```powershell
ping topaz.local.dev
```

Le résultat doit indiquer une résolution vers :

```text
127.0.0.1
```

Vérifier ensuite l'accès au port utilisé par Topaz :

```powershell
Test-NetConnection topaz.local.dev -Port 8899
```

La valeur suivante doit apparaître :

```text
TcpTestSucceeded : True
```

## 2. Ouvrir PowerShell dans le projet

Depuis le dossier racine du projet, exécuter :

```powershell
Set-ExecutionPolicy -Scope Process Bypass
```

Cette modification concerne uniquement la session PowerShell actuelle.

## 3. Créer le laboratoire et lancer le scan

```powershell
.\scripts\quickstart.ps1
```

Cette commande démarre Topaz, initialise le laboratoire Azure fictif et lance le scan.

## Démarrer uniquement le laboratoire

```powershell
.\scripts\start-lab.ps1
```

## Relancer uniquement le scan

Pour scanner de nouveau l'environnement existant :

```powershell
.\scripts\scan-topaz.ps1
```

## Réinitialiser le laboratoire

Pour reconstruire complètement l'environnement de test :

```powershell
.\scripts\reset-lab.ps1
```

## Arrêter le laboratoire

Pour arrêter Topaz tout en conservant l'état du laboratoire :

```powershell
.\scripts\stop-lab.ps1
```

## Architecture d'exécution

```text
Docker
   ↓
Topaz
   ↓
Azure-like API locale
   ↓
lab.py / scripts d'initialisation
   ↓
Ressources Azure fictives
   ↓
azure.py
   ↓
RBAC / Storage / Compute / Network / Resources
   ↓
Discovery
   ↓
Analysis
   ↓
Scoring
   ↓
Reporting
```