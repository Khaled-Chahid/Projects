# E-BK-03 : test de restauration et entretien sauvegardes

**Document simulé.** Aucune restauration réelle n’a été exécutée. Les résultats chiffrés ci-dessous appartiennent au scénario.

## Rapport TEST-BK-0912

Date du test : 12 septembre 2026. Intervenants du cas : IT et prestataire. Point utilisé : copie distante du 11 septembre, 23 h 35. Début du test : 9 h 00 ; fin : 9 h 37. Le point a 9 h 25 au début de l’essai.

Vingt fichiers de mission sont restaurés dans un répertoire isolé. Les vingt comparaisons d’empreintes sont identiques. Le responsable opérations confirme la lisibilité des documents. Durée totale du test fichiers : **37 minutes**.

Limite consignée par l’intervenant : « L’annuaire DC-01, les droits des partages et l’accès au service complet ne sont pas restaurés dans cet essai. » Cette durée ne valide donc pas le délai de reprise du service.

## Entretien simulé du 7 octobre 2026

Objet : expliquer le dossier arrêté au 30 septembre.

| Question | Réponse consignée dans le cas |
| --- | --- |
| Les tâches locales couvrent-elles les deux composants ? | La configuration remise inclut les fichiers de FS-01 et l’état système de DC-01. Les sept journaux locaux portent ce libellé. |
| Comment est séparée la copie distante ? | Un compte de stockage dédié est utilisé. IT remet le paramétrage de rétention 14 jours local / 30 jours distant. Le dossier ne prouve pas l’immutabilité. |
| Pourquoi aucun ticket pour les trois échecs distants ? | Le référent était absent. La boîte partagée n’a pas été suivie et aucun relais n’était désigné. |
| Le stockage distant est-il définitivement inaccessible ? | Non établi. Le diagnostic n’a pas été documenté. |
| Existe-t-il un autre essai trimestriel complet ? | Aucun n’est remis. Le test du 12 septembre a été limité aux fichiers, faute de procédure et de créneau isolé pour l’annuaire. |
| Comment la direction suit-elle les tests ? | Retour oral après les exercices, sans tableau consolidé remis. |

Les informations de séparation et de rétention sont déclarées dans ce dossier documentaire. Aucun contrôle direct du stockage n’est réalisé.
