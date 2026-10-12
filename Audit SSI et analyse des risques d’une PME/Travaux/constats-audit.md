# Constats d’audit

Situation examinée au 30 septembre 2026. Fiches établies à partir de preuves synthétiques. Les non-conformités ci-dessous sont des écarts aux règles internes du cas.

<a id="fe-01"></a>

## FE-01 : Deux comptes actifs après départ

**Qualification :** Non-conformité interne. **Priorité proposée :** P1.

**Critère :** POL-AC v1.2, §3 : retrait des accès au plus tard à la fin du dernier jour de travail ; ticket de clôture vérifié par IT.

**Rapprochement ISO :** A.5.18 (droits d’accès)

**Fait établi dans le cas :** Les comptes l.moreau et s.benali sont actifs au 30 septembre, avec accès VPN autorisé, alors que les départs sont datés des 18 et 25 septembre. Les tickets DEP-0918 et DEP-0925 restent ouverts. L'exposition dure respectivement 12 et 5 jours à la date de l'export.

**Portée et limites :** L'export ne démontre ni connexion après départ ni consultation de dossiers. Deux autres départs de l'échantillon ont été traités dans le délai prévu.

**Cause proposée à confirmer :** Le rapprochement des tickets RH et de l'annuaire n'est pas systématique. Cette explication provient de l'entretien, sans analyse de cause indépendante.

**Preuves :** E-AC-01, E-AC-02, E-AC-03. Voir l’[index des preuves](../Preuves/index.md).

**Suite :** R-01 ; [ACT-01](plan-actions.md#act-01). Statut du constat : ouvert.

<a id="fe-02"></a>

## FE-02 : Revue des droits arrivée à échéance

**Qualification :** Non-conformité interne. **Priorité proposée :** P2.

**Critère :** POL-AC v1.2, §4 : revue trimestrielle par les responsables métier et revue à chaque changement de poste.

**Rapprochement ISO :** A.5.18 (droits d’accès)

**Fait établi dans le cas :** La dernière revue produite est datée du 30 juin. Celle prévue au 30 septembre n'est pas fournie. Le transfert de m.girard au 1er août ne comporte pas de validation des groupes dans le ticket MOB-0801.

**Portée et limites :** Les groupes conservés ne suffisent pas à conclure à un accès illégitime : un besoin de transition peut exister et doit être validé par le métier.

**Cause proposée à confirmer :** La revue trimestrielle n'a pas de relance ni de suppléant. Le manager a différé la revue, selon l'entretien simulé.

**Preuves :** E-AC-01, E-AC-02, E-AC-04. Voir l’[index des preuves](../Preuves/index.md).

**Suite :** R-02 ; [ACT-02](plan-actions.md#act-02). Statut du constat : ouvert.

<a id="fe-03"></a>

## FE-03 : Compte privilégié partagé entre deux intervenants

**Qualification :** Non-conformité interne. **Priorité proposée :** P1.

**Critère :** POL-AC v1.2, §5 : administration avec un compte nominatif distinct du compte bureautique ; compte commun uniquement comme secours tracé.

**Rapprochement ISO :** A.8.2 (privilèges) et A.5.16 (identités)

**Fait établi dans le cas :** Le compte it.admin, membre de Domain Admins, est utilisé quotidiennement par le responsable IT et le prestataire. L'entretien confirme que le secret est partagé via un coffre. Aucun registre d'usage de secours n'est fourni.

**Portée et limites :** La présence du compte ne prouve pas une compromission. L'existence et la configuration du coffre ne sont pas testées dans cette étude documentaire.

**Cause proposée à confirmer :** La pratique historique du prestataire n'a pas été alignée sur la politique approuvée en janvier.

**Preuves :** E-AC-01, E-AC-02, E-AC-04. Voir l’[index des preuves](../Preuves/index.md).

**Suite :** R-03 ; [ACT-03](plan-actions.md#act-03). Statut du constat : ouvert.

<a id="fe-04"></a>

## FE-04 : Échecs de copie distante sans traitement tracé

**Qualification :** Non-conformité interne. **Priorité proposée :** P1.

**Critère :** POL-BK v1.1, §3 : contrôle chaque matin ; ticket en cas d’échec ; escalade au responsable IT après deux échecs consécutifs.

**Rapprochement ISO :** A.8.13 (sauvegarde)

**Fait établi dans le cas :** Les copies distantes des 27, 28 et 29 septembre échouent. Aucune prise en charge ni ticket n'apparaît dans les trois lignes. La dernière copie distante réussie est celle du 26 septembre à 23 h 35. Les sauvegardes locales réussissent sur la période examinée.

**Portée et limites :** La rétention de 30 jours ne garantit pas la fraîcheur des copies. Le dossier ne démontre pas de perte de données ni de panne de la copie locale.

**Cause proposée à confirmer :** La boîte de notifications n'a pas été consultée pendant l'absence de l'intervenant habituel. Aucun relais n'était nommé, selon l'entretien.

**Preuves :** E-BK-01, E-BK-02. Voir l’[index des preuves](../Preuves/index.md).

**Suite :** R-04 ; [ACT-04](plan-actions.md#act-04). Statut du constat : ouvert.

<a id="fe-05"></a>

## FE-05 : Test de reprise incomplet au regard de la politique

**Qualification :** Non-conformité interne. **Priorité proposée :** P1.

**Critère :** POL-BK v1.1, §4 : test trimestriel incluant fichiers, annuaire et vérification du service ; objectif de reprise de 8 h et perte maximale de 24 h.

**Rapprochement ISO :** A.8.13 (sauvegarde)

**Fait établi dans le cas :** Le test du 12 septembre restaure 20 fichiers en 37 minutes, avec comparaison d'empreintes concluante. Le rapport indique explicitement que l'annuaire et le service complet ne sont pas testés. Aucun autre test trimestriel couvrant ces dépendances n'est remis.

**Portée et limites :** 37 minutes est un délai de restauration de fichiers ; il ne valide pas l'objectif de reprise de 8 h du service complet. L'écart ne démontre pas l'impossibilité technique de restaurer.

**Cause proposée à confirmer :** Le test a été réduit aux fichiers faute de procédure et de créneau pour un exercice isolé de l'annuaire.

**Preuves :** E-BK-01, E-BK-03. Voir l’[index des preuves](../Preuves/index.md).

**Suite :** R-05 ; [ACT-05](plan-actions.md#act-05). Statut du constat : ouvert.

<a id="fe-06"></a>

## FE-06 : Suivi de direction peu consolidé

**Qualification :** Observation. **Priorité proposée :** P2.

**Critère :** Objectif de suivi du mandat : rendre visibles les retards et les décisions sur les deux processus.

**Rapprochement ISO :** 9.1 (suivi) et 10.2 (actions correctives), rapprochement indicatif

**Fait établi dans le cas :** Les responsables sont désignés, mais aucun tableau commun des départs non clôturés, des revues en retard et des échecs de copie n'est remis. Les échanges sont principalement oraux.

**Portée et limites :** Le dossier contient des traces opérationnelles et une gouvernance minimale. L'absence d'un tableau unique ne suffit pas à établir une non-conformité à ISO 27001.

**Cause proposée à confirmer :** Chaque intervenant suit son activité séparément, sans consolidation périodique.

**Preuves :** E-GOV-01, E-AC-04, E-BK-03. Voir l’[index des preuves](../Preuves/index.md).

**Suite :** R-01 à R-05 (facteur transversal, sans risque supplémentaire) ; [ACT-06](plan-actions.md#act-06). Statut du constat : ouvert.
