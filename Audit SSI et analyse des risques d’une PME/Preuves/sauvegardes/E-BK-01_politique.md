# E-BK-01 : politique de sauvegarde et de restauration

Document simulé d’Orbe Services. Référence interne : **POL-BK v1.1**. Approbation dans le scénario : 2 février 2026. Propriétaire : responsable IT. État remis : 30 septembre 2026.

## 1. Couverture et fréquence

BK-01 sauvegarde chaque soir à 22 h les dossiers de FS-01 et l’état système de DC-01. Une copie distante démarre après la sauvegarde locale. Les objectifs métier sont une reprise du service en 8 heures au maximum et une perte maximale de données de 24 heures.

## 2. Rétention et séparation

La rétention locale est de 14 jours et la rétention distante de 30 jours. Le stockage distant utilise un compte dédié distinct des comptes d’administration de domaine. Les accès sont limités à IT et au prestataire. La copie distante n’est pas déclarée immuable dans ce dossier.

## 3. Contrôle et traitement des échecs

Le prestataire vérifie chaque matin les tâches locale et distante. Un échec entraîne l’ouverture d’un ticket avec diagnostic et reprise. Deux échecs consécutifs sont escaladés au responsable IT. Les notifications vont à une boîte partagée. Le document ne désigne pas de suppléant en cas d’absence.

## 4. Tests

Chaque trimestre, IT réalise un test isolé comprenant des fichiers, l’annuaire et la vérification des accès au service restauré. Le compte rendu décrit le point utilisé, l’intégrité des données, les durées et la validation métier. Le test compare les résultats aux objectifs de 8 h/24 h.

## 5. Conservation des preuves

Les journaux d’exécution et les rapports de tests sont conservés douze mois. Les échecs restent ouverts tant que la reprise n’a pas été vérifiée.
