# SNGA Dispatch Relay Console - CTF Writeup

## 📋 Table des matières
1. [Analyse de la cible et du mécanisme de signature](#1-analyse-de-la-cible-et-du-mécanisme-de-signature)
2. [Le principe de l'attaque par extension de longueur](#2-le-principe-de-lattaque-par-extension-de-longueur)
3. [La logique du parseur ("Last Value Wins")](#3-la-logique-du-parseur-last-value-wins)
4. [La recherche de la longueur de la clé (Brute-force intelligent)](#4-la-recherche-de-la-longueur-de-la-clé-brute-force-intelligent)
5. [Validation et obtention du flag](#5-validation-et-obtention-du-flag)
6. [Script de résolution (`solve.py`) & Explication ligne par ligne](#6-script-de-résolution-solvepy--explication-ligne-par-ligne)

---

## 1. Analyse de la cible et du mécanisme de signature
En lisant la spécification (`/api/spec`) et l'échantillon récupéré (`/api/sample`), on découvre comment fonctionne la sécurité du système :
- **Le format de signature :** `tag = SHA-256(key_bytes || message_bytes)`
- Le serveur calcule un hachage SHA-256 en préfaçant un secret (la clé) directement devant les octets du message.
- **Le problème de conception :** Il s'agit d'un hachage simple avec préfixe (`Hash(secret || message)`), et non d'un HMAC (qui utilise une structure cryptographique imbriquée plus robuste). C'est la porte ouverte à une faille critique appelée **Attaque par extension de longueur (Length Extension Attack)**.

---

## 2. Le principe de l'attaque par extension de longueur
Imaginons que vous connaissiez :
1. Un message valide $M_1$ (par exemple : `station=CORRIDOR-3&cmd=STATUS&ts=1764182323&nonce=cf45949e`).
2. Sa signature $\text{sig}_1$ (le hash SHA-256 résultant de $\text{key} \parallel M_1$).
3. La longueur de la clé secrète (ou une estimation/plage de cette longueur).

Même sans connaître la valeur de la clé, la structure interne de SHA-256 permet de prendre l'état de hachage atteint à la fin de $M_1$ et de continuer le calcul en y ajoutant de nouvelles données ($M_2$).

Pour cela, il faut :
- Recréer le **padding SHA-256** exact qui complète le message d'origine jusqu'à la fin du bloc de 64 octets.
- Concaténer l'extension souhaitée (dans notre cas, `&cmd=DISPATCH`).
- Demander à l'algorithme de reprendre le calcul du hash à partir de l'ancienne signature comme état initial.

---

## 3. La logique du parseur ("Last Value Wins")
Le challenge introduit une subtilité intéressante dans la spécification du parseur :
> *"split the command bytes on '&'; split each token on the first '='; keep tokens whose key matches ^[A-Za-z][A-Za-z0-9_]*$; last value wins"*
> `command_field`: `"cmd"`

Lorsque le serveur lit notre message forgé, il décode la chaîne de caractères qui contient :
1. Le message d'origine (`station=CORRIDOR-3&cmd=STATUS...`)
2. Le padding binaire de SHA-256 (qui ressemble à des octets non affichables ou des caractères nuls).
3. Notre ajout à la fin : `&cmd=DISPATCH`.

Le parseur va analyser tous les paramètres séparés par `&`. Il verra donc `cmd=STATUS` au début, puis plus loin (après les octets de padding), il verra `cmd=DISPATCH`. Comme la règle est **"la dernière valeur l'emporte"** (*last value wins*), le paramètre `cmd` est écrasé et passe de `STATUS` à `DISPATCH`.

---

## 4. La recherche de la longueur de la clé (Brute-force intelligent)
La spécification indiquait une bande de longueur de clé, mais pour s'affranchir d'une incertitude sur la taille exacte, le script de résolution a testé itérativement toutes les longueurs de clé possibles (de 1 à 64 octets) :

```python
for kl in range(1, 65):
    new_sig, new_msg_bytes = hashpumpy.hashpump(sig, original_message, addition, kl)
    ...
```

Dès que la longueur de clé correcte a été injectée dans l'algorithme `hashpump`, le hachage mathématique calculé correspondait exactement à ce que le serveur attendait pour valider la signature.

---

## 5. Validation et obtention du flag
1. **Génération du payload :** Le script a produit un nouveau bloc d'octets hexadécimaux (`message_hex`) contenant le message original, le padding SHA-256 et `&cmd=DISPATCH`, ainsi qu'une nouvelle signature valide (`sig`).
2. **Envoi de la requête :** Le script a envoyé ces éléments via une requête HTTP `POST` sur l'endpoint `/api/command`.
3. **Vérification du serveur :**
   - Le serveur a recalculé le SHA-256 avec sa clé secrète sur les octets reçus. Grâce à la propriété mathématique de l'attaque par extension, le hash correspondait à la signature fournie. Le serveur a donc considéré la requête comme authentique.
   - Le serveur a ensuite exécuté le parseur, vu que `cmd=DISPATCH` était présent en fin de chaîne (grâce à la règle *last value wins*), et a validé l'action privilégiée.
4. **Résultat :** Le serveur a débloqué l'accès et renvoyé l'autorisation contenant le flag au format `CSCTF{...}`.

---

## 6. Script de résolution (`solve.py`) & Explication ligne par ligne

```python
import urllib.request
import json
import hashpumpy
import binascii

# Échantillon capturé depuis /api/sample
sig = "217521e9ddefffa11fb045d9f6a9a145ccba47b6625ee5cc48743a9ba3662848"
original_message = b"station=CORRIDOR-3&cmd=STATUS&ts=1764182323&nonce=cf45949e"
addition = "&cmd=DISPATCH"
url = "http://w02.ctf.chronos-security.ro:32808/api/command"

# Boucle pour tester toutes les longueurs de clé de 1 à 64 octets
for kl in range(1, 65):
    try:
        new_sig, new_msg_bytes = hashpumpy.hashpump(sig, original_message, addition, kl)
        new_message_hex = binascii.hexlify(new_msg_bytes).decode()
        
        payload = {
            "message_hex": new_message_hex,
            "sig": new_sig
        }
        
        data = json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(
            url, 
            data=data, 
            headers={'Content-Type': 'application/json'}
        )
        
        with urllib.request.urlopen(req) as response:
            print(f"[+] Succès avec key_length = {kl} !")
            print("Response:", response.read().decode('utf-8'))
            break
    except urllib.error.HTTPError:
        continue
```

### Explication ligne par ligne :
- **`import ...`** : Importe les bibliothèques pour gérer le réseau (`urllib`), le format JSON, l'algorithme d'extension de longueur (`hashpumpy`) et la conversion hexadécimale (`binascii`).
- **`sig`, `original_message`, `addition`** : Paramètres de base extraits de l'échantillon `/api/sample` et charge utile malveillante que l'on souhaite rajouter.
- **`for kl in range(1, 65):`** : Parcourt les tailles de clés potentielles pour contourner l'inconnue de la longueur exacte du secret.
- **`hashpumpy.hashpump(...)`** : Recrée mathématiquement le padding SHA-256 et prolonge l'état du hash pour générer la nouvelle signature (`new_sig`) et le message étendu (`new_msg_bytes`).
- **`binascii.hexlify(...).decode()`** : Convertit le message binaire étendu au format hexadécimal attendu par l'API (`message_hex`).
- **`urllib.request.Request(...)` & `urlopen`** : Construit et envoie la requête HTTP POST contenant le payload JSON vers l'instance cible.
- **`print(...)` et `break`** : Si le serveur valide la requête (pas d'erreur HTTP 400), le script affiche la réponse contenant le flag et s'arrête.
