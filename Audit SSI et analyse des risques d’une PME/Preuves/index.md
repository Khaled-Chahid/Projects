# Index des preuves

Tous les documents et exports de ce dossier sont **synthétiques**. Ils représentent les éléments remis dans une mission simulée. Les politiques conservent leurs limites et les exports leurs anomalies : les résultats de l’audit figurent dans `Travaux/`.

| Référence | Fichier | Date / portée |
| --- | --- | --- |
| E-GOV-01 | [Responsabilités](E-GOV-01_responsabilites.md) | Note du 15 janvier ; état remis au 30 septembre |
| E-AC-01 | [Politique accès](acces/E-AC-01_politique.md) | POL-AC v1.2, 15 janvier |
| E-AC-02 | [Export comptes](acces/E-AC-02_comptes.csv) | Dix comptes sélectionnés, 30 septembre |
| E-AC-03 | [Mouvements RH et tickets](acces/E-AC-03_mouvements.csv) | Huit mouvements, juillet à septembre |
| E-AC-04 | [Revue et entretien accès](acces/E-AC-04_revue-et-entretien.md) | Revue du 30 juin ; entretien simulé du 6 octobre |
| E-BK-01 | [Politique sauvegarde](sauvegardes/E-BK-01_politique.md) | POL-BK v1.1, 2 février |
| E-BK-02 | [Journal des tâches](sauvegardes/E-BK-02_journal.csv) | Sept nuits, 23 au 29 septembre |
| E-BK-03 | [Test et entretien sauvegardes](sauvegardes/E-BK-03_test-et-entretien.md) | Test du 12 septembre ; entretien simulé du 7 octobre |

## Dictionnaire des exports

Les fichiers utilisent UTF-8, des virgules et des dates ISO `AAAA-MM-JJ`. Une cellule vide indique une information **non fournie**, et non une valeur nulle ou une opération exécutée.

- **Comptes** : `personne` rapproche le compte du registre RH. Les groupes sont séparés par `;`. `actif` et `vpn` sont les états déclarés au 30 septembre. L’export ne contient ni tentatives de connexion ni journaux d’activité.
- **Mouvements** : `date_effet` désigne l’arrivée, la mobilité ou le dernier jour de travail. `execution_it` indique la date de traitement fournie. « Ouvert » ne prouve pas une action malveillante.
- **Sauvegardes** : chaque ligne représente une nuit et ses deux étapes. Une réussite locale ne garantit pas la réussite distante. Les champs de contrôle et de ticket décrivent les traces remises.

L’absence de ticket est étayée, dans le cas, par le journal et l’entretien correspondant. Les sept nuits ne permettent pas d’estimer une fiabilité annuelle.
