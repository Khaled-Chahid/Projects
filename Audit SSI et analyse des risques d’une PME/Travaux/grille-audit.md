# Grille d’audit

Mission simulée AUD-2026-01. Les résultats satisfaisants restent limités à la concordance documentaire et à l’échantillon.

| Test | Sujet | Critère testé | Preuves | Résultat | Conclusion / limite |
| --- | --- | --- | --- | --- | --- |
| C-01 | Périmètre et objectifs | Deux processus, actifs, responsables et objectifs identifiés. | E-GOV-01 | Satisfaisant | Périmètre documenté ; pas de conclusion globale SMSI. |
| C-02 | Responsabilités | Responsables RH, métier, IT et direction désignés. | E-GOV-01 | Satisfaisant | Les rôles sont explicites ; suppléance examinée séparément. |
| C-03 | Arrivées | Approbation métier avant activation sur les trois arrivées. | E-AC-01 / E-AC-03 | Satisfaisant | ARR-0701, ARR-0810 et ARR-0901 approuvés avant la date d’effet. |
| C-04 | Départs | Compte et VPN désactivés avant fin du dernier jour. | E-AC-01 / E-AC-02 / E-AC-03 | Non-conformité interne | 2 cas non traités sur 4 départs : FE-01. |
| C-05 | Revue et mobilité | Revue trimestrielle et décision lors du changement de poste. | E-AC-01 / E-AC-02 / E-AC-04 | Non-conformité interne | Revue de septembre non remise ; mobilité sans décision : FE-02. |
| C-06 | Privilèges | Comptes administratifs individuels ; secours exceptionnel tracé. | E-AC-01 / E-AC-02 / E-AC-04 | Non-conformité interne | it.admin partagé en usage quotidien : FE-03. |
| C-07 | Compte de service | Propriétaire, finalité et absence d’accès interactif. | E-AC-01 / E-AC-02 / E-AC-04 | Satisfaisant | svc.backup identifié ; configuration déclarée, sans connexion réelle. |
| C-08 | Accès VPN | MFA déclaré pour les comptes nominatifs actifs examinés. | E-AC-01 / E-AC-02 / E-AC-04 | Satisfaisant | État documentaire cohérent ; ne valide ni la révocation ni l’efficacité du MFA. |
| C-09 | Couverture sauvegarde | Tâches couvrant FS-01 et l’état système de DC-01. | E-BK-01 / E-BK-02 / E-BK-03 | Satisfaisant | Libellés et entretien cohérents ; restaurabilité examinée séparément. |
| C-10 | Rétention et séparation | Paramètres 14/30 jours et compte distant distinct. | E-BK-01 / E-BK-03 | Satisfaisant | Concordance documentaire ; aucune immutabilité ou résistance au ransomware démontrée. |
| C-11 | Traitement des échecs | Contrôle quotidien, ticket et escalade après deux échecs. | E-BK-01 / E-BK-02 / E-BK-03 | Non-conformité interne | 3 échecs distants consécutifs sans prise en charge : FE-04. |
| C-12 | Restauration de fichiers | Rapport d’essai, intégrité et validation métier. | E-BK-03 | Satisfaisant | 20 fichiers et 20 empreintes identiques en 37 min ; résultat limité aux fichiers. |
| C-13 | Reprise du service | Test trimestriel complet, objectifs de 8 h/24 h. | E-BK-01 / E-BK-03 | Non-conformité interne | Annuaire et service complet non testés : FE-05. |
| C-14 | Suivi de direction | Visibilité des retards, actions et décisions. | E-GOV-01 / E-AC-04 / E-BK-03 | Observation | Pas de consolidation remise ; aucun tableau unique imposé : FE-06. |

**Bilan :** 14 tests, dont 8 satisfaisants sur l’échantillon, 5 non-conformités internes et 1 observation. Les cinq non-conformités ne sont pas cinq vulnérabilités techniques démontrées.

Les références des preuves se trouvent dans l’[index](../Preuves/index.md). Les justifications développées figurent dans les [fiches d’écart](constats-audit.md).
