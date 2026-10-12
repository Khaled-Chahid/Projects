# Méthodologie

## Nature de la mission

Cette étude simule un audit interne ciblé. Elle s’appuie sur ISO/IEC 27001:2022 et sur les règles de l’entreprise fictive. Elle ne constitue pas un audit de certification, une attestation de conformité ou une analyse EBIOS RM. Aucun autre référentiel n’est annoncé.

Les preuves d’entreprise sont synthétiques et explicitement identifiées comme telles. Les conclusions décrivent ce que ces preuves permettent d’établir dans le cas. Une lacune documentaire n’est pas automatiquement une défaillance technique.

## Critères et rapprochements

| Sujet | Rapprochement ISO 27001 retenu |
| --- | --- |
| Délimitation de la mission | 4.3 |
| Affectation des rôles | 5.3 |
| Appréciation et traitement des risques | 6.1.2 et 6.1.3 |
| Planification et restitution de l’audit interne | 9.2 |
| Suivi des résultats et actions correctives | 9.1 et 10.2 |
| Accès, identités et droits | A.5.15, A.5.16 et A.5.18 |
| Privilèges administratifs | A.8.2 |
| Sauvegarde et essais de restauration | A.8.13 |

Ce tableau est une sélection pédagogique. Les mesures de l’Annexe A ne sont pas toutes obligatoires par défaut : leur choix découle des risques et des besoins. Les clauses 4 à 10 restent nécessaires pour une revendication de conformité complète, qui n’est pas l’objet de cette étude.

La grille teste des critères internes reformulés, sans reproduire le texte normatif. Les fréquences trimestrielles, le retrait des accès le jour du départ et les objectifs de 8 h/24 h sont les choix de l’entreprise simulée. Ils ne sont pas présentés comme des prescriptions chiffrées d’ISO 27001.

## Collecte et échantillonnage

1. Lire le contexte, les politiques et les responsabilités.
2. Rapprocher les départs et la mobilité des comptes et des tickets.
3. Examiner les privilèges et la validation des accès.
4. Rapprocher les journaux de sauvegarde du traitement des échecs.
5. Comparer la portée du test de restauration à la politique.
6. Consigner les résultats, leurs limites et les explications des entretiens simulés.
7. Définir les scénarios de risque et les actions, puis prévoir les vérifications d’efficacité.

L’échantillon des dix comptes est orienté : les quatre départs du trimestre, une mobilité, trois salariés actifs, un compte privilégié commun et un compte de service. Le registre RH comprend aussi trois arrivées dont les approbations sont vérifiées. Les exports ne sont pas des inventaires exhaustifs des 24 salariés.

Les journaux couvrent sept nuits, du 23 au 29 septembre. Le test remis date du 12 septembre. Aucun taux du cas n’est extrapolé à toute l’entreprise.

## Qualification des résultats

- **Satisfaisant sur l’échantillon** : le critère testé dispose d’éléments cohérents. Cela ne vaut pas conformité globale du processus.
- **Non-conformité interne** : un critère précis d’une politique du cas n’est pas respecté dans les preuves.
- **Observation** : amélioration proposée ou incertitude, sans preuve suffisante pour déclarer une non-conformité.

Les termes « majeure » et « mineure » ne sont pas utilisés : aucun schéma de certification n’est appliqué. La priorité d’action est distincte de la nature du constat. Une cause issue d’un entretien reste une explication à confirmer.

## Appréciation des risques

L’horizon de réflexion est de douze mois à partir du 30 septembre 2026. La vraisemblance est qualitative ; les niveaux ne correspondent pas à des probabilités statistiques.

| Niveau | Vraisemblance | Impact maximal plausible |
| --- | --- | --- |
| 1 | Peu plausible : prérequis difficiles et contrôles crédibles | Limité : gêne inférieure à 2 h, travail récupérable, pas de diffusion sensible |
| 2 | Possible : scénario crédible, exposition partielle ou maîtrise incertaine | Significatif : perturbation de 2 à 8 h ou reprise manuelle limitée |
| 3 | Plausible : faiblesse confirmée et scénario accessible | Important : perturbation de plus de 8 h à 48 h, divulgation sensible ou reprise coûteuse |
| 4 | Très plausible : exposition directe avec moyens de maîtrise largement absents | Majeur : perturbation de plus de 48 h, perte durable ou atteinte étendue à plusieurs services |

L’impact est le maximum raisonnablement retenu parmi confidentialité, intégrité et disponibilité. Les durées ne sont pas cumulées avec des impacts financiers fictifs. Chaque scénario justifie ses notes séparément.

**Score = vraisemblance × impact.** C’est un indice de classement, pas une mesure de perte attendue.

| Score | Niveau | Traitement proposé dans le cas |
| --- | --- | --- |
| 1 à 3 | Faible | Acceptation possible et suivi par le propriétaire |
| 4 à 7 | Modéré | Décision motivée ; planification d’une réduction ou acceptation par la direction |
| 8 à 11 | Élevé | Réduction prioritaire ; acceptation exceptionnelle motivée par la direction |
| 12 à 16 | Critique | Mesure immédiate et plan prioritaire ; aucune acceptation implicite |

La direction conserve la décision. Les cinq risques sont proposés à la réduction, y compris le risque modéré. Leur score actuel tient compte des contrôles existants. Un risque inhérent supplémentaire n’est pas calculé.

Les scores cibles supposent les actions réalisées **et leur efficacité vérifiée**. Ils ne remplacent pas les scores actuels. Aucun risque résiduel observé n’est déclaré, car aucune mise en œuvre n’a été réalisée. La revue prévue pourra confirmer, modifier ou refuser ces cibles.

## Correction et suivi

La correction traite la situation constatée. L’action corrective prévient sa répétition. La clôture exige une preuve de réalisation et un test d’efficacité distinct. Toutes les actions sont au statut « Proposée » dans cette version ; aucune signature ni approbation réelle n’est simulée comme acquise.

La revue du 30 novembre 2026 est un rendez-vous proposé. Les décisions d’acceptation, les changements de notes et la clôture y restent à documenter.

## Sources publiques

Consultation : 11 octobre 2026. Le support de cours fourni a servi de repère pédagogique pour le SMSI et le cycle d’amélioration ; il n’est pas redistribué.

- [ISO, présentation d’ISO/IEC 27001:2022](https://www.iso.org/standard/27001).
- [IEC, notice de la publication ISO/IEC 27001:2022](https://webstore.iec.ch/en/publication/79694).
- [ISO/IEC JTC 1/SC 27, note sur la déclaration d’applicabilité](https://committee.iso.org/files/live/sites/jtc1sc27/files/resources/ISO-IECJTC1-SC27-WG1_N3298_Auditing%20Practices%20Note%20-%20SoA.pdf).

Ces sources éclairent le cadre. Les critères opérationnels et le barème sont propres au cas. Le dépôt ne contient pas de copie de la norme ni de SoA complète.
