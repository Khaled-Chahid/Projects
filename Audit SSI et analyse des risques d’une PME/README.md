# Audit interne et analyse des risques SSI d’une PME

Étude de cas simulée fondée sur des exigences et des mesures sélectionnées d’ISO/IEC 27001:2022.

Le dossier porte sur **la gestion des accès** et **les sauvegardes et la restauration** d’Orbe Services, une PME fictive de 24 salariés. L’audit rapproche les règles internes des documents et des traces opérationnelles. Les écarts alimentent une analyse de risques et un plan d’actions avec responsables, échéances et critères de clôture.

**La société, les personnes, les entretiens et toutes les preuves sont fictifs.** Les exports CSV sont des données synthétiques. Aucun accès à une entreprise réelle ni test d’intrusion n’a été réalisé. L’étude est ciblée et ne conclut pas à la conformité globale ni à la certification d’un SMSI.

## Résultats

- 14 points de contrôle documentaires : 8 satisfaisants sur l’échantillon, 5 non-conformités aux règles internes et 1 observation.
- 5 scénarios de risque : 1 critique, 3 élevés et 1 modéré selon le barème du cas.
- 6 actions proposées. Les scores après traitement sont des **cibles conditionnelles**, pas des résultats obtenus.

Le partage d’un compte d’administration est la priorité principale. Les deux comptes non désactivés après départ et les échecs de copie distante appellent aussi une correction rapide. Des pratiques utiles existent : validation des nouveaux accès, copie distante distincte et test de restauration de fichiers réussi.

## Lecture du dossier

| Document | Contenu |
| --- | --- |
| [Rapport final](Rapport/rapport-final.md) / [PDF](Rapport/rapport-final.pdf) | Conclusion, résultats et décisions proposées |
| [Scénario](Scenario/contexte.md) | Entreprise, actifs, dépendances et responsabilités |
| [Méthodologie](methodologie.md) | Critères, échantillon, barème et limites |
| [Preuves](Preuves/index.md) | Index des documents et des exports synthétiques |
| [Plan d’audit](Travaux/plan-audit.md) | Mandat, périmètre et programme de la mission |
| [Grille de contrôle](Travaux/grille-audit.md) | Tests effectués et résultats détaillés |
| [Fiches d’écart](Travaux/constats-audit.md) | Critère, preuve, constat, portée et cause à confirmer |
| [Analyse de risques](Travaux/analyse-risques.md) | Scénarios et justification des évaluations |
| [Plan d’actions](Travaux/plan-actions.md) | Correction, prévention et vérification d’efficacité |
| [Registre Excel](Rapport/registre-risques.xlsx) / [CSV](Travaux/registre-risques.csv) | Évaluations et suivi |

## Exemple de traçabilité

L’[export des comptes E-AC-02](Preuves/acces/E-AC-02_comptes.csv) et le [registre RH E-AC-03](Preuves/acces/E-AC-03_mouvements.csv) montrent deux accès conservés après départ. La règle concernée figure dans [E-AC-01](Preuves/acces/E-AC-01_politique.md). Le résultat est documenté dans [FE-01](Travaux/constats-audit.md#fe-01), puis évalué comme [R-01](Travaux/analyse-risques.md#r-01) et traité par [ACT-01](Travaux/plan-actions.md#act-01).

## Organisation

- `Scenario/` : contexte du cas.
- `Preuves/` : documents de l’entreprise simulée, conservés tels qu’examinés.
- `Travaux/` : analyses de l’auditeur.
- `Rapport/` : restitution Markdown, PDF et registre Excel.

Les fichiers Markdown se lisent directement dans le dépôt. Les PDF et XLSX sont des versions de restitution. Aucun programme ni installation n’est nécessaire.

## Référence

[ISO/IEC 27001:2022](https://www.iso.org/standard/27001) est le seul référentiel annoncé. Les clauses et les mesures de l’Annexe A sont des rapprochements sélectionnés. Les constats sont établis sur les règles internes explicites du scénario. La norme complète n’est pas reproduite dans le dépôt.
