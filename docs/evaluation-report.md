# Rapport d'évaluation : détection par règles, Isolation Forest et DBSCAN

**Statut : brouillon. Aucun résultat réel n'est encore disponible.**

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

À COMPLÉTER : nombre de sessions, nombre d'attaques, tableau identique à 5.1, composition des clusters DBSCAN (`cluster_report`).

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

À COMPLÉTER après les résultats réels.