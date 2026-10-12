# Orbe Services : contexte de l’étude

**Cas fictif.** Les noms, dates, volumes et objectifs ci-dessous sont des hypothèses de travail.

## Activité et données

Orbe Services réalise des prestations de conseil opérationnel pour une vingtaine de clients. Ses 24 salariés produisent des rapports, des contrats et des dossiers de mission. Le serveur de fichiers contient environ 600 Go de documents, dont des coordonnées professionnelles, des propositions commerciales et des livrables confidentiels.

La remise des livrables dépend de l’accès aux dossiers clients. Une interruption en journée reporte les travaux ; une perte de données oblige à reconstituer les documents auprès des équipes. La direction fixe un objectif de reprise du service de **8 heures** et une perte maximale de données de **24 heures**. Ce sont des objectifs métier du cas, pas des valeurs imposées par ISO 27001.

## Système d’information étudié

| Actif | Fonction et dépendances | Responsable |
| --- | --- | --- |
| DC-01 | Annuaire Active Directory, authentification et résolution de noms | Responsable IT |
| FS-01 | Partages clients ; accès dépendant de DC-01 et des groupes métier | Responsable opérations |
| BK-01 | Copie locale quotidienne des fichiers et de l’état système | Responsable IT |
| Copie distante | Copie des sauvegardes vers le prestataire, compte dédié distinct | Responsable IT |
| VPN | Accès distant nominatif avec MFA, droits gérés par IT | Responsable IT |
| Registre RH | Arrivées, mobilités et départs transmis à IT | Responsable administratif |

Le domaine `orbe.example` est un nom réservé utilisé pour la documentation. Aucune adresse de production n’est fournie. Le dossier ne contient pas de machines virtuelles et ne représente pas un système déployé.

## Responsabilités

| Rôle | Décisions et tâches |
| --- | --- |
| Direction | Approuve les politiques, les moyens et l’acceptation des risques |
| Responsable administratif | Tient les mouvements RH et déclenche les demandes IT |
| Responsable opérations | Valide le besoin d’accès, les revues de droits et la reprise métier |
| Responsable IT | Administre les comptes, les sauvegardes et le suivi des incidents techniques |
| Prestataire IT | Exécute les opérations déléguées et fournit les journaux et comptes rendus |
| Auditeur du cas | Compare les preuves aux critères, rapporte les résultats et propose des actions |

Le rôle d’auditeur est distinct des responsables des processus dans le scénario. La même étude produit les données et les analyses à des fins pédagogiques : l’indépendance n’a donc pas été démontrée dans une entreprise réelle.

## Documents disponibles au 30 septembre 2026

La direction a approuvé une politique d’accès en janvier et une politique de sauvegarde en février. Les tâches sont partagées entre un responsable IT interne et un prestataire. Certains contrôles fonctionnent, mais la traçabilité des exceptions et des relances est inégale.

Le dossier comprend un extrait de dix comptes, huit mouvements RH, sept nuits de journaux et un test de restauration. La période de l’audit documentaire va du 5 au 9 octobre, sur une photographie opérationnelle arrêtée au 30 septembre. Le rapport est daté du 11 octobre 2026.

## Limites du périmètre

L’étude couvre les accès aux dossiers clients et les moyens de sauvegarde/restauration qui les soutiennent. Elle ne couvre pas l’ensemble du SMSI, la sécurité physique, le code des applications, les obligations juridiques détaillées, un PCA/PRA complet ou les autres services de l’entreprise. Les dépendances sont prises en compte dans les scénarios, sans être auditées intégralement.

Les données clients sensibles sont la finalité de protection. Elles ne constituent pas un troisième domaine de contrôle ajouté au périmètre.
