# Rapport d'évaluation : détection par règles, Isolation Forest et DBSCAN

**Statut : évaluation réelle effectuée le 20/11/2026 sur 23 sessions labellisées (Cowrie uniquement). Résultats en section 5.2.**

Les chiffres de la section 5 viennent de données synthétiques et ne mesurent aucune performance réelle.

## 1. Objectif

Comparer trois approches pour repérer des sessions suspectes sur des événements normalisés :

1. détection par règles (avec corrélation en incidents) ;
2. Isolation Forest (non supervisé) ;
3. DBSCAN (regroupement exploratoire).

## 2. Unité d'évaluation

La **session**, identifiée par `(source, session_id)`.

- Les événements Juice Shop n'ont pas de `session_id` (le log Nginx ne contient que 6 champs). Ils ne sont **pas évalués** ici.
- Une adresse IP n'est jamais utilisée pour relier des événements.

## 3. Méthodes

**Règles.** Règles simples, à seuil, de séquence, de commande et HTTP. Une session est « signalée » si elle produit un incident de sévérité `medium` ou plus.

**Features.** 9 features numériques par session, calculées uniquement à partir des événements (jamais des sorties de règles, pour éviter une fuite de données) : nombre d'événements, d'échecs, de succès, de commandes, types d'événements distincts, noms d'utilisateur distincts, durée, fréquence, ratio d'échecs. Aucun texte, aucune IP.

**Isolation Forest.** Non supervisé, features standardisées, `contamination = 0,1` fixée a priori, graine fixe. Entraîné sur un jeu, évalué sur un autre.

**DBSCAN.** Features standardisées, `min_samples = 5`, `eps` choisi sans labels (90e percentile de la distance au 5e voisin). Les clusters sont **interprétés** avec les labels, pas utilisés comme prédictions.

## 4. Métriques

Precision = TP / (TP + FP) ; Recall = TP / (TP + FN) ;

F1 = 2TP / (2TP + FP + FN) ; FPR = FP / (FP + TN).

Une métrique à dénominateur nul est notée **n/a** (jamais 0). Les formules sont vérifiées par des tests calculés à la main et par comparaison avec scikit-learn.

## 5. Résultats

### 5.1 Données synthétiques (test du pipeline uniquement)

| Méthode | TP | FP | FN | TN | Precision | Recall | F1 | FPR |
|---|---|---|---|---|---|---|---|---|
| Règles | 42 | 46 | 3 | 209 | 0,477 | 0,933 | 0,632 | 0,180 |
| Isolation Forest | 31 | 13 | 14 | 242 | 0,705 | 0,689 | 0,697 | 0,051 |

300 sessions, 45 attaques (15 %), graines 1 (entraînement) et 2 (test).

**Ces chiffres dépendent entièrement du générateur que nous avons écrit. Ils ne doivent pas être cités comme des performances.**

### 5.2 Données réelles (scénarios de Person 1)

**Résultats réels (23 sessions labellisées, toutes évaluées, 0 sans événements).**

23 sessions au total : 12 attaques, 11 normales (TP + FN = 12, FP + TN = 11).

| Méthode | TP | FP | FN | TN | Precision | Recall | F1 | FPR |
|---|---|---|---|---|---|---|---|---|
| Règles | 7 | 0 | 5 | 11 | 1,000 | 0,583 | 0,737 | 0,000 |
| Isolation Forest | 1 | 2 | 11 | 9 | 0,333 | 0,083 | 0,133 | 0,182 |

Rappel : `contamination = 0,1`, graine fixe 42, entraînement et évaluation sur les mêmes 23 sessions (pas de jeu de test séparé).

**Lecture.** Sur ces données, les règles ont une précision parfaite (aucun faux positif) mais ratent 5 attaques (rappel 0,583). Isolation Forest est nettement moins bon : précision 0,333, rappel 0,083, F1 0,133, et 2 faux positifs (FPR 0,182). Les règles restent la meilleure approche sur ce jeu.

**Points à traiter (inchangés) :**
- faux positifs des règles : aucuns sur ce jeu ;
- faux négatifs : 5 attaques ratées, à analyser (quelle règle, quelle session) ;
- sessions signalées par Isolation Forest qui ne sont pas des attaques : une anomalie n'est pas une attaque ;
- DBSCAN non évalué ici (clustering exploratoire, voir `src/ml/dbscan.py`).

### 5.3 Évaluation avec séparation train/test (hold-out)

Méthode : les sessions sont réparties en train (entraînement de l'Isolation Forest) et test (évaluation), stratifiées par label, avec graine fixe. Les règles ne s'entraînent pas (pas de fuite). L'Isolation Forest nécessite au moins 20 sessions d'entraînement.

| Split (train/test) | Sessions train | Sessions test | Règles (F1) | Isolation Forest (F1) |
|---|---|---|---|---|
| 70 / 30 | 16 | 7 | 0,400 | non exécuté (< 20 train) |
| 87 / 13 | 20 | 3 | 0,667 | 0,000 |

**Conclusion : le jeu de données est trop petit pour une validation hold-out fiable.** Avec 23 sessions, on ne peut pas à la fois entraîner l'Isolation Forest (≥ 20 sessions) et garder un jeu de test assez grand pour des métriques significatives (3 sessions = aucune puissance statistique). Les résultats ci-dessus ne doivent pas être cités comme des performances.

### 5.4 Données nécessaires pour une validation sérieuse

1. **Au moins 100 sessions par classe** (attaques et normales), soit 200+ sessions Cowrie labellisées. Les 23 actuelles ne suffisent pas.
2. **Un jeu de validation séparé** : entraînement sur un sous-ensemble, validation sur un autre, test sur un troisième. Les seuils (`contamination`, `eps`) ne doivent jamais être ajustés sur le jeu de test.
3. **Plusieurs graines aléatoires** : reporter la moyenne et l'écart-type, pas un seul run.
4. **Sessions Juice Shop** : actuellement exclues (pas de `session_id`). Il faut dériver un identifiant de session sûr pour le trafic web, ou accepter que le ML ne couvre que Cowrie.
5. **Labels équilibrés** : le ratio actuel (12 attaques / 11 normales) est artificiel. Le ratio réel est à mesurer sur du trafic non scénarisé.

## 6. Analyse

À COMPLÉTER avec les résultats réels. Points à traiter :

- faux positifs des règles (quelle règle, quelles sessions) ;
- faux négatifs (quelles attaques sont ratées, pourquoi) ;
- sessions signalées par Isolation Forest qui ne sont pas des attaques : une anomalie n'est pas une attaque ;
- clusters DBSCAN : pureté, part d'attaques dans le bruit.

## 7. Limites

1. **Données synthétiques** : générées par nous, avec une zone de chevauchement choisie par nous.
2. **Corrélation des méthodes** : règles et ML regardent surtout les échecs de connexion ; ils ne sont pas indépendants.
3. **Sous-échantillon de Cowrie** : seules les sessions Cowrie sont évaluables.
4. **Déséquilibre de classes** : 15 % d'attaques en synthétique ; le ratio réel est à mesurer.
5. **Réglage** : seuils des règles, `contamination` et `eps` ne doivent pas être ajustés sur le jeu de test. Il faut un jeu de validation séparé.
6. **Logs Nginx** : `route` sans query string, pas de corps de requête, IP possiblement celle de la passerelle.
7. **Champ de commande** : à vérifier sur de vrais logs (`input` ou `command`).
8. **Unité unique** : l'évaluation par événement ou par scénario n'est pas faite.
9. **IP uniforme dans le laboratoire** : toutes les sessions du laboratoire ont la même `src_ip` (passerelle Docker, confirmé par Person 1). Aucune règle ni feature n'utilise l'IP, donc l'évaluation n'est pas affectée, mais `src_ip` n'a aucune valeur analytique sur ces données.

## 8. Reproductibilité

```bash
python -m pytest -q
python -m src.ml.compare_methods
```

Graines fixes, entrées triées, résultats déterministes.

## 9. Conclusion

Sur les 23 sessions labellisées (12 attaques, 11 normales), les règles surpassent Isolation Forest : précision 1,000 contre 0,333, rappel 0,583 contre 0,083, F1 0,737 contre 0,133, et FPR 0,000 contre 0,182. Les règles ne produisent aucun faux positif sur ce jeu, au prix de 5 faux négatifs à analyser.

Ces résultats confirment le choix architectural : le pipeline en production repose sur les règles, qui sont transparentes et testables, et l'apprentissage automatique reste une comparaison hors ligne. Les chiffres reposent sur des données de laboratoire scriptées (22 sessions + 1), avec entraînement et évaluation sur les mêmes sessions : ils sont optimistes et ne se généralisent pas. Un jeu de validation séparé et davantage de sessions labellisées sont nécessaires avant toute intégration.