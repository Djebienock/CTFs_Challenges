# Résolution du Challenge CTF : Offline Forensics - Abandoned Tracker

## 1. Contexte du problème
Un utilisateur cherchait à déterminer le lieu où il se rendait le plus souvent sur "autopilote". Pour cela, il croisait deux signaux captés par son téléphone :
- Le nombre de pas effectués (`step_delta`).
- Les points d'accès Wi-Fi environnants et leur puissance (`signal`).

L'objectif est d'analyser les artefacts restants (`notes.txt`, `aps.conf`, `scan_export.csv`, `run.log`) pour reconstruire l'algorithme de calcul de score et identifier le lieu final.

---

## 2. Analyse des artefacts et des règles

### A. Filtrage des points d'accès (`aps.conf`)
Le fichier `aps.conf` contient la liste des réseaux autorisés ainsi que leur poids de confiance ($w$) respectif :
- `FoxgloveCoffee_Guest` ($w = 3$)
- `HomePlex_5G` ($w = 2$)
- `CafeDelMundo` ($w = 2$)
- `NETGEAR-8841` ($w = 1$)

*Note : Tous les autres points d'accès présents dans l'export (comme `xfinitywifi`, `Starbucks`, etc.) sont ignorés.*

### B. Seuil de mouvement (`run.log`)
Dans le fichier de log `run.log`, on analyse le comportement du script sur `CafeDelMundo` :
```text
signal=62  step_delta= 40  -> stationary, dropped
signal=58  step_delta= 41  -> moving, kept
```
- Une valeur de `step_delta` de **40** est considérée comme "stationnaire" (rejetée).
- Une valeur de `step_delta` de **41** est considérée comme "en mouvement" (conservée).

**Règle définie :** `step_delta > 40` (ou $\ge 41$).

### C. Formule de calcul du score
Le score global par point d'accès est calculé selon la formule :

$$\text{Score} = \text{poids (w)} \times \sum \text{signal (pour les mesures où } \text{step\_delta} > 40)$$

---

## 3. Application du modèle sur l'export (`scan_export.csv`)

### 1. `FoxgloveCoffee_Guest` ($w = 3$)
| Timestamp | Signal | Step Delta | État | Signal conservé |
| :--- | :---: | :---: | :---: | :---: |
| 2026-01-28 07:51:14 | 68 | 72 | Conservé | 68 |
| 2026-01-28 12:10:14 | 71 | 88 | Conservé | 71 |
| 2026-01-28 14:38:14 | 66 | 54 | Conservé | 66 |
| 2026-01-28 19:34:14 | 73 | 95 | Conservé | 73 |
| 2026-01-28 23:53:14 | 70 | 61 | Conservé | 70 |
| 2026-01-29 04:12:14 | 74 | 12 | Rejeté | - |
| 2026-01-29 09:08:14 | 69 | 8 | Rejeté | - |

- **Somme des signaux conservés :** $68 + 71 + 66 + 73 + 70 = 348$
- **Score final :** $348 \times 3 = \mathbf{1044}$

---

### 2. `CafeDelMundo` ($w = 2$)
| Timestamp | Signal | Step Delta | État | Signal conservé |
| :--- | :---: | :---: | :---: | :---: |
| 2026-02-02 05:01:14 | 60 | 58 | Conservé | 60 |
| 2026-02-02 17:58:14 | 64 | 77 | Conservé | 64 |
| 2026-02-03 09:23:14 | 58 | 41 | Conservé | 58 |
| 2026-02-04 01:25:14 | 62 | 40 | Rejeté | - |

- **Somme des signaux conservés :** $60 + 64 + 58 = 182$
- **Score final :** $182 \times 2 = \mathbf{364}$

---

### 3. `NETGEAR-8841` ($w = 1$)
| Timestamp | Signal | Step Delta | État | Signal conservé |
| :--- | :---: | :---: | :---: | :---: |
| 2026-02-04 19:18:14 | 80 | 66 | Conservé | 80 |
| 2026-02-05 11:57:14 | 78 | 52 | Conservé | 78 |
| 2026-02-06 07:04:14 | 82 | 90 | Conservé | 82 |
| 2026-02-07 04:02:14 | 79 | 30 | Rejeté | - |

- **Somme des signaux conservés :** $80 + 78 + 82 = 240$
- **Score final :** $240 \times 1 = \mathbf{240}$

---

### 4. `HomePlex_5G` ($w = 2$)
Toutes les lignes ont un `step_delta` inférieur ou égal à 40 sauf une :
- `2026-02-01 09:17:14` : `signal = 87`, `step_delta = 44` (Conservé)

- **Somme des signaux conservés :** $87$
- **Score final :** $87 \times 2 = \mathbf{174}$

---

## 4. Classement Final

| Rang | Nom du point d'accès | Score Total |
| :---: | :--- | :---: |
| **1** | **`FoxgloveCoffee_Guest`** | **1044** |
| 2 | `CafeDelMundo` | 364 |
| 3 | `NETGEAR-8841` | 240 |
| 4 | `HomePlex_5G` | 174 |

---

## 5. Flag Final

Le point d'accès ayant le score le plus élevé est **`FoxgloveCoffee_Guest`**.

**Flag :** `hiCTF{FoxgloveCoffee_Guest}`
