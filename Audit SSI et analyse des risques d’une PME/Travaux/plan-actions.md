# Plan d’actions et vérification d’efficacité

Version du 11 octobre 2026. Toutes les actions sont **proposées**, sans réalisation ni approbation acquise. Les échéances sont des dates recommandées à partir de la restitution.

P1 : correction rapide pour risque élevé ou critique. P2 : amélioration planifiée ou risque modéré. L’ordre de lancement tient aussi compte des dépendances et des délais.

| Action | Constat | Responsable d’exécution | Validation proposée | Priorité | Échéance |
| --- | --- | --- | --- | --- | --- |
| [ACT-01](#act-01) | FE-01 | Responsable IT | Responsable administratif | P1 | 2026-10-12 |
| [ACT-02](#act-02) | FE-02 | Responsable opérations | Direction | P2 | 2026-10-23 |
| [ACT-03](#act-03) | FE-03 | Responsable IT | Direction | P1 | 2026-10-16 |
| [ACT-04](#act-04) | FE-04 | Responsable IT | Responsable opérations | P1 | 2026-10-14 |
| [ACT-05](#act-05) | FE-05 | Responsable IT | Responsable opérations | P1 | 2026-10-30 |
| [ACT-06](#act-06) | FE-06 | Responsable administratif | Direction | P2 | 2026-10-23 |

Le responsable d’exécution réalise la tâche ; le propriétaire du risque valide l’effet métier. La direction arbitre les moyens et les exceptions.

<a id="act-01"></a>

## ACT-01 : FE-01

**Correction immédiate :** Désactiver les deux comptes et le VPN ; révoquer les sessions actives ; conserver les journaux avant clôture.

**Prévention de la répétition :** Ajouter une confirmation IT obligatoire au départ et un rapprochement hebdomadaire RH/annuaire avec suppléant.

**Preuve de réalisation attendue :** Export daté, tickets clôturés, trace de retrait VPN et contrôle des sessions.

**Vérification d’efficacité :** Vérifier les quatre départs historiques puis les trois prochains départs : clôture avant fin du dernier jour et validation RH/IT.

**Dépendance :** Signalement RH avant le départ ; accès administratif disponible.

**Risques liés :** R-01. **Échéance :** 2026-10-12. **Revue proposée :** 2026-11-30.

**Suivi :** approbation à décider ; réalisation non engagée ; preuve non reçue ; efficacité non vérifiée ; clôture non autorisée.

<a id="act-02"></a>

## ACT-02 : FE-02

**Correction immédiate :** Terminer la revue du trimestre ; faire confirmer ou retirer les groupes de m.girard.

**Prévention de la répétition :** Planifier la revue, nommer un suppléant et intégrer les changements de poste aux demandes IT.

**Preuve de réalisation attendue :** Matrice de droits validée, décisions motivées par groupe et ticket MOB-0801 traité.

**Vérification d’efficacité :** Contrôler dix comptes et le prochain changement de poste ; aucune attribution sans justification métier.

**Dépendance :** Disponibilité des responsables métier.

**Risques liés :** R-02. **Échéance :** 2026-10-23. **Revue proposée :** 2026-11-30.

**Suivi :** approbation à décider ; réalisation non engagée ; preuve non reçue ; efficacité non vérifiée ; clôture non autorisée.

<a id="act-03"></a>

## ACT-03 : FE-03

**Correction immédiate :** Créer deux comptes administratifs nominatifs ; tester les opérations ; retirer it.admin de l’usage quotidien après contrôle des dépendances.

**Prévention de la répétition :** Limiter les privilèges au besoin ; encadrer un éventuel compte de secours et tracer chaque usage.

**Preuve de réalisation attendue :** Groupes mis à jour, ticket de migration et journaux associés aux comptes individuels.

**Vérification d’efficacité :** Échantillon de cinq opérations : attribution à un intervenant et absence de dépendance au compte partagé.

**Dépendance :** Coordination avec le prestataire et fenêtre de changement.

**Risques liés :** R-03. **Échéance :** 2026-10-16. **Revue proposée :** 2026-11-30.

**Suivi :** approbation à décider ; réalisation non engagée ; preuve non reçue ; efficacité non vérifiée ; clôture non autorisée.

<a id="act-04"></a>

## ACT-04 : FE-04

**Correction immédiate :** Diagnostiquer les trois échecs ; reprendre la copie distante et vérifier un point restaurable récent.

**Prévention de la répétition :** Router l’alerte vers un responsable et un suppléant ; ouvrir un ticket et escalader après deux échecs consécutifs.

**Preuve de réalisation attendue :** Ticket d’incident de sauvegarde, journal de reprise et test contrôlé de notification.

**Vérification d’efficacité :** Simuler un échec sans données de production puis vérifier sept nuits de copie distante et la prise en charge des alertes.

**Dépendance :** Disponibilité du stockage distant et accès au portail prestataire.

**Risques liés :** R-04. **Échéance :** 2026-10-14. **Revue proposée :** 2026-11-30.

**Suivi :** approbation à décider ; réalisation non engagée ; preuve non reçue ; efficacité non vérifiée ; clôture non autorisée.

<a id="act-05"></a>

## ACT-05 : FE-05

**Correction immédiate :** Réaliser un exercice isolé de restauration de DC-01 et FS-01 avec contrôle des accès métier.

**Prévention de la répétition :** Documenter les dépendances, les étapes, les rôles et le test trimestriel du service complet.

**Preuve de réalisation attendue :** Compte rendu chronométré, point de sauvegarde utilisé et validation métier des fichiers et accès.

**Vérification d’efficacité :** Reprise du service en 8 h au maximum et point restauré vieux de 24 h au maximum ; sinon conserver l’écart ouvert.

**Dépendance :** Capacité de laboratoire isolé et créneau prestataire.

**Risques liés :** R-05. **Échéance :** 2026-10-30. **Revue proposée :** 2026-11-30.

**Suivi :** approbation à décider ; réalisation non engagée ; preuve non reçue ; efficacité non vérifiée ; clôture non autorisée.

<a id="act-06"></a>

## ACT-06 : FE-06

**Correction immédiate :** Consolider les résultats et affecter chaque action à un responsable.

**Prévention de la répétition :** Tenir une revue mensuelle des départs, droits, copies, exercices et risques ouverts.

**Preuve de réalisation attendue :** Compte rendu de revue daté avec décisions, exceptions et échéances.

**Vérification d’efficacité :** Le 30 novembre, rapprocher chaque action des preuves ; garder ouverts les dossiers non démontrés.

**Dépendance :** Données RH, IT et prestataire disponibles.

**Risques liés :** R-01, R-02, R-03, R-04, R-05. **Échéance :** 2026-10-23. **Revue proposée :** 2026-11-30.

**Suivi :** approbation à décider ; réalisation non engagée ; preuve non reçue ; efficacité non vérifiée ; clôture non autorisée.

## Conditions de clôture

Un ticket fermé ne suffit pas : la preuve doit correspondre à l’action et le test d’efficacité doit être concluant. L’évaluateur vérifie les éléments, le propriétaire valide la situation et la direction accepte les risques restants si nécessaire. Une réduction supposée ne permet pas de remplacer le score actuel par le score cible.
