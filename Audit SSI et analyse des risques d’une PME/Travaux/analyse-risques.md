# Analyse des risques

Évaluation au 30 septembre 2026, horizon de douze mois. Méthode et seuils : [méthodologie](../methodologie.md). Aucun incident réel n’est déclaré.

## Registre synthétique

| Risque | Propriétaire | V | I | Score actuel | Niveau | Score cible | Actions |
| --- | --- | --- | --- | --- | --- | --- | --- |
| [R-01](#r-01) : Accès conservé après un départ | Responsable administratif | 3 | 3 | 9 | Élevé | 3, Faible | ACT-01 |
| [R-02](#r-02) : Droits excessifs non détectés | Responsable opérations | 2 | 3 | 6 | Modéré | 3, Faible | ACT-02 |
| [R-03](#r-03) : Usage non attribuable de privilèges | Responsable IT | 3 | 4 | 12 | Critique | 4, Modéré | ACT-03 |
| [R-04](#r-04) : Perte de données faute de copie récente | Responsable opérations | 3 | 3 | 9 | Élevé | 3, Faible | ACT-04 |
| [R-05](#r-05) : Reprise du service non démontrée | Responsable opérations | 2 | 4 | 8 | Élevé | 4, Modéré | ACT-05 |

Les scores cibles ne sont pas des risques résiduels vérifiés. Les actions restent proposées et les risques restent ouverts. ACT-06 soutient le suivi des cinq risques sans créer un scénario supplémentaire.

<a id="r-01"></a>

## R-01 : Accès conservé après un départ

**Propriétaire :** Responsable administratif

**Actifs concernés :** Dossiers clients, annuaire et accès VPN

**Besoins affectés :** Confidentialité, intégrité

**Scénario :** Un ancien salarié utilise un accès encore actif pour consulter ou modifier des dossiers clients.

**Situation favorisant le risque :** Deux comptes de salariés partis restent actifs et autorisés sur le VPN au 30 septembre.

**Mesures existantes :** Comptes nominatifs, MFA sur le VPN, procédure de départ formalisée.

**Vraisemblance 3/4 :** Les deux accès sont encore ouverts. Le MFA ne retire pas un accès légitime à son ancien titulaire. Aucun usage après départ n'est établi.

**Impact 3/4 :** Des dossiers clients pourraient être divulgués ou altérés, avec une reprise manuelle et une rupture de confiance commerciale.

**Évaluation actuelle :** 3 × 3 = 9, niveau élevé.

**Traitement proposé :** réduire. ACT-01 et suivi ACT-06. Approbation et acceptation éventuelle : à décider par la direction.

**Cible conditionnelle :** V=1, I=3, score 3 (faible). Une clôture vérifiée à chaque départ et un rapprochement RH/IT réduisent l'exposition. La sensibilité des dossiers reste identique.

**Traçabilité :** FE-01 ; E-AC-01, E-AC-02, E-AC-03.

<a id="r-02"></a>

## R-02 : Droits excessifs non détectés

**Propriétaire :** Responsable opérations

**Actifs concernés :** Dossiers clients et groupes de partage

**Besoins affectés :** Confidentialité, intégrité

**Scénario :** Un salarié consulte ou modifie des dossiers hors de sa mission à la suite d'un changement de poste non revu.

**Situation favorisant le risque :** Aucune revue trimestrielle n'est fournie depuis juin et un transfert interne n'a pas déclenché de revue des groupes.

**Mesures existantes :** Approbation des nouveaux accès par le responsable métier, groupes par équipe.

**Vraisemblance 2/4 :** Le retard de revue et le transfert créent une possibilité crédible. L'échantillon ne démontre pas que les droits du salarié sont effectivement excessifs.

**Impact 3/4 :** Des données clients pourraient être accessibles en dehors du besoin métier. Le niveau d'impact reste celui de dossiers sensibles.

**Évaluation actuelle :** 2 × 3 = 6, niveau modéré.

**Traitement proposé :** réduire. ACT-02 et suivi ACT-06. Approbation et acceptation éventuelle : à décider par la direction.

**Cible conditionnelle :** V=1, I=3, score 3 (faible). La revue métier et le contrôle des changements de poste réduisent la plausibilité, sous réserve d'une décision motivée sur chaque groupe.

**Traçabilité :** FE-02 ; E-AC-01, E-AC-02, E-AC-04.

<a id="r-03"></a>

## R-03 : Usage non attribuable de privilèges

**Propriétaire :** Responsable IT

**Actifs concernés :** Annuaire, serveur de fichiers et configuration de sauvegarde

**Besoins affectés :** Confidentialité, intégrité, disponibilité

**Scénario :** Le compte d'administration partagé est compromis ou utilisé abusivement pour modifier les droits ou supprimer des données, sans attribution individuelle fiable.

**Situation favorisant le risque :** Deux intervenants utilisent le même compte privilégié, contrairement à la règle interne.

**Mesures existantes :** Accès administratif via VPN avec MFA et coffre de mots de passe déclaré dans le dossier.

**Vraisemblance 3/4 :** Le partage est confirmé dans l'entretien simulé. Le coffre réduit l'exposition du secret, mais n'attribue pas l'action réalisée avec ce compte.

**Impact 4/4 :** Le privilège permet une atteinte étendue aux services et à la restauration. Une interruption de plus de 48 heures est un impact plausible, non une durée mesurée.

**Évaluation actuelle :** 3 × 4 = 12, niveau critique.

**Traitement proposé :** réduire. ACT-03 et suivi ACT-06. Approbation et acceptation éventuelle : à décider par la direction.

**Cible conditionnelle :** V=1, I=4, score 4 (modéré). Des comptes d'administration distincts, le retrait du compte commun et une vérification des journaux réduisent le risque. Le privilège conserve un impact élevé.

**Traçabilité :** FE-03 ; E-AC-01, E-AC-02, E-AC-04.

<a id="r-04"></a>

## R-04 : Perte de données faute de copie récente

**Propriétaire :** Responsable opérations

**Actifs concernés :** Dossiers clients sur FS-01

**Besoins affectés :** Intégrité, disponibilité

**Scénario :** Une suppression ou une panne survient pendant une série d'échecs de copie distante et oblige à restaurer un point trop ancien si la copie locale est aussi indisponible.

**Situation favorisant le risque :** Trois copies distantes consécutives échouent sans ticket ni escalade documentée.

**Mesures existantes :** Copie locale quotidienne, copie distante isolée par un compte distinct, rétention distante de 30 jours, test fichier réussi.

**Vraisemblance 3/4 :** Les échecs et l'absence de réaction sont observés dans les données simulées. Une copie locale reste disponible ; aucune perte effective n'est constatée.

**Impact 3/4 :** Le dernier point distant disponible le 30 septembre est daté du 26 septembre. La reprise peut exiger plusieurs jours de ressaisie.

**Évaluation actuelle :** 3 × 3 = 9, niveau élevé.

**Traitement proposé :** réduire. ACT-04 et suivi ACT-06. Approbation et acceptation éventuelle : à décider par la direction.

**Cible conditionnelle :** V=1, I=3, score 3 (faible). Une alerte testée, une reprise de copie contrôlée et un suppléant limitent la fenêtre d'exposition. L'impact d'une perte de données reste important.

**Traçabilité :** FE-04 ; E-BK-01, E-BK-02, E-BK-03.

<a id="r-05"></a>

## R-05 : Reprise du service non démontrée

**Propriétaire :** Responsable opérations

**Actifs concernés :** DC-01, FS-01 et dépendances de restauration

**Besoins affectés :** Disponibilité

**Scénario :** Une panne majeure rend l'annuaire et le serveur de fichiers indisponibles. Les équipes ne rétablissent pas le service dans le délai métier prévu.

**Situation favorisant le risque :** Le test trimestriel porte sur des fichiers, sans restauration de l'annuaire ni mesure du délai de reprise du service complet.

**Mesures existantes :** Sauvegarde des fichiers et de l'état système, inventaire des composants, test de 20 fichiers avec contrôle d'intégrité.

**Vraisemblance 2/4 :** La dépendance à l'annuaire est connue. L'absence d'exercice complet crée une incertitude crédible, mais ne prouve pas que la restauration échouera.

**Impact 4/4 :** Une reprise prolongée bloque les dossiers clients et les échéances. Un arrêt supérieur à 48 heures constitue le scénario d'impact retenu.

**Évaluation actuelle :** 2 × 4 = 8, niveau élevé.

**Traitement proposé :** réduire. ACT-05 et suivi ACT-06. Approbation et acceptation éventuelle : à décider par la direction.

**Cible conditionnelle :** V=1, I=4, score 4 (modéré). Un exercice isolé de bout en bout et un mode opératoire validé réduisent l'incertitude. La gravité reste élevée si le service devient indisponible.

**Traçabilité :** FE-05 ; E-BK-01, E-BK-03.

## Revue et décision

À la revue proposée du 30 novembre, le propriétaire confirme les réalisations et l’auditeur contrôle les preuves et l’efficacité. La direction décide de l’acceptation éventuelle et fixe la prochaine revue. Si une preuve manque, le score actuel reste la référence et l’action demeure ouverte.
