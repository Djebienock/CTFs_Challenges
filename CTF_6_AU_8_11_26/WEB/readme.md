# Write-up CTF Forensics Web — Operation Dawn (Annex Entry 07)

## 📌 Présentation du Challenge
- **Nom :** Operation Dawn, annex entry 07
- **Catégorie :** Forensics / Web
- **Fichier fourni :** `access.log` (Format Nginx combined + champ `rt=`)
- **Format du Flag :** `CSCTF{...}`

---

## 🔍 Contextualisation et Objectif
La coalition a saisi les logs d'un serveur web contrôlé par l'« Ash Army ». Un attaquant est parvenu à exfiltrer un secret (token/lien de vérification) depuis la base de données via le portail d'état (`/api/status`), sans jamais déclencher d'erreur HTTP 500 ou 404 (toutes les requêtes renvoyaient des codes HTTP 200).

L'objectif était d'analyser le fichier de logs `access.log`, d'isoler l'activité de l'attaquant, de comprendre sa technique d'exfiltration, et de reconstruire le secret extrait.

---

## 🚀 Étapes de Résolution

### Étape 1 : Identification de l'adresse IP de l'attaquant
Étant donné que l'exfiltration s'effectue caractère par caractère (injection SQL aveugle), l'attaquant génère un nombre disproportionné de requêtes par rapport à un utilisateur légitime.

Nous avons utilisé `awk`, `sort` et `uniq` pour compter le nombre de requêtes renvoyant un statut HTTP 200 par IP.

```bash
awk '$9 == 200 {print $1}' access.log | sort | uniq -c | sort -nr
```

**Résultat :**
L'IP `198.51.100.66` ressort immédiatement avec **2666 requêtes**, loin devant les autres utilisateurs.

---

### Étape 2 : Extraction du trafic malveillant
Une fois l'IP identifiée, nous avons extrait uniquement ses requêtes réussies (HTTP 200) dans un fichier de travail dédié.

```bash
grep "198.51.100.66" access.log | grep " 200 " > attacker_requests.log
```

---

### Étape 3 : Analyse des requêtes d'injection SQL (Time-Based SQLi)
En inspectant les premières lignes de `attacker_requests.log` avec `head` :

```bash
head -n 5 attacker_requests.log
```

Nous avons observé le motif d'attaque suivant :
```http
GET /api/status?unit=43'+AND+IF(SUBSTR(token,6,1)='Z',SLEEP(2),0)--+- HTTP/1.1" 200 33 "-" "python-requests/2.32.3" rt=0.057
```

**Analyse de l'attaque :**
- **Vecteur :** Injection SQL aveugle basée sur le temps (*Time-Based Blind SQLi*) sur le paramètre `unit`.
- **Mécanisme :** L'attaquant teste si un caractère de la chaîne `token` à l'index $N$ est égal à un caractère donné : `SUBSTR(token, pos, 1) = 'c'`.
- **Condition de succès :** Si l'affirmation est vraie, la fonction `SLEEP(2)` s'exécute, provoquant un délai de réponse de 2 secondes. Le temps de réponse est consigné à la fin de chaque ligne de log via la variable Nginx `rt` (ex: `rt=2.003`).

---

### Étape 4 : Script d'extraction et de reconstruction automatique
Pour chaque position $N$ du token, le caractère valide est celui pour lequel `rt > 1.5` secondes. Nous avons conçu un script Python (`solve.py`) pour parser `attacker_requests.log`, isoler les paires `(position, caractère)` validées par le délai, puis réassembler le flag.

```python
import re
import urllib.parse

log_file = "attacker_requests.log"
flag_chars = {}

with open(log_file, "r") as f:
    for line in f:
        # Extraire la position et le caractère testé
        match = re.search(r'SUBSTR\(token,\s*(\d+),\s*1\)\s*=\s*\'([^\']+)\'', line)
        if match:
            pos = int(match.group(1))
            char = match.group(2)
            
            # Extraire le temps de réponse (rt=...)
            rt_match = re.search(r'rt=([\d.]+)', line)
            if rt_match:
                rt = float(rt_match.group(1))
                
                # Un rt supérieur à 1.5s indique que le SLEEP(2) a été déclenché
                if rt > 1.5:
                    flag_chars[pos] = urllib.parse.unquote(char)

# Reconstitution dans l'ordre des indices
secret = "".join([flag_chars[p] for p in sorted(flag_chars.keys())])
print(f"Secret récapitulé : {secret}")
```

---

## 🛠 Explication Détaillée des Commandes Utilisées

### 1. Filtrage et comptage des IP :
```bash
awk '$9 == 200 {print $1}' access.log | sort | uniq -c | sort -nr
```
- `awk '$9 == 200 {print $1}'` : 
  - Dans le format Nginx combined, la 9ᵉ colonne (`$9`) correspond au code de réponse HTTP (ex: 200, 404). 
  - La 1ʳᵉ colonne (`$1`) correspond à l'adresse IP du client. 
  - Cette instruction ne conserve que l'adresse IP si le code HTTP est `200`.
- `| sort` : Trie les adresses IP par ordre alphabétique/numérique (étape requise par la commande `uniq`).
- `| uniq -c` : Regroupe les lignes identiques contiguës et affiche le nombre d'occurrences pour chacune (`-c` = count).
- `| sort -nr` : Trie le résultat final numériquement (`-n`) et par ordre décroissant (`-r` = reverse) pour faire apparaître l'IP la plus active en haut de la liste.

### 2. Isolation du trafic de l'attaquant :
```bash
grep "198.51.100.66" access.log | grep " 200 " > attacker_requests.log
```
- `grep "198.51.100.66"` : Ne conserve que les lignes contenant l'adresse IP ciblée.
- `grep " 200 "` : Filtre une deuxième fois pour s'assurer de ne garder que les réponses HTTP avec le code de succès 200.
- `> attacker_requests.log` : Redirige le résultat dans un fichier texte séparé pour simplifier l'analyse ultérieure.

### 3. Inspection rapide des données :
```bash
head -n 5 attacker_requests.log
```
- `head -n 5` : Affiche les 5 premières lignes du fichier spécifié pour observer la structure des requêtes HTTP et des charges utiles (*payloads*) d'injection SQL.
