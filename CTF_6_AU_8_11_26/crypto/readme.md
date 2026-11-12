# CTF Writeup: Emergency Logistics Dispatch Signing (Crypto)

## 📋 Description du Challenge
Un service de signature logistique d'urgence a redémarré après une restauration incorrecte de son état interne (problème de réutilisation de nonce). Le dossier fourni contient un export JSON (`signing-export.json`) comprenant des métadonnées, la clé publique ECDSA (`secp256k1`) et un ensemble de 8 enregistrements de dispatch signés.

**Objectif :** Déterminer si la clé de signature a été compromise, retrouver le scalaire privé (la clé privée), et soumettre le résultat sous le format de flag requis : `CSCTF{<64_caractères_hexadécimaux_minuscules>}`.

---

## 🔍 Étape 1 : Analyse des Signatures et Détection de la Vulnérabilité

En examinant le fichier `signing-export.json`, on analyse la structure des signatures ECDSA (`r || s`). 

Pour l'algorithme ECDSA sur la courbe `secp256k1`, chaque signature est composée de deux grands entiers $(r, s)$ générés à l'aide d'un nombre aléatoire éphémère appelé **nonce ($k$)** :
$$s = k^{-1} (z + r \cdot d) \pmod n$$

* **Le problème critique :** Si deux messages différents $m_1$ et $m_2$ (de hachages respectifs $z_1$ et $z_2$) sont signés en utilisant **la même clé privée $d$** et **le même nonce $k$**, alors la valeur de $r$ sera strictement identique pour ces deux signatures.

En parcourant les enregistrements (`records`), on repère rapidement deux messages qui partagent exactement le même préfixe $r$ dans leur signature `signature_rs_hex` (les 32 premiers octets) :
1. **`R-6103`** (`"insulin cold boxes"`):
   * `r` : `821f300799a645e288df87f4e1913c60606c13aa50cae4804a375890887b4f4a`
2. **`R-6107`** (`"medical radio packs"`):
   * `r` : `821f300799a645e288df87f4e1913c60606c13aa50cae4804a375890887b4f4a`

Puisque $r$ est identique, **le nonce $k$ a été réutilisé**, ce qui rend la clé privée vulnérable à une récupération mathématique directe.

---

## 🧮 Étape 2 : Résolution Mathématique (Extraction de la Clé Privée)

Connaissant deux signatures $(r, s_1)$ et $(r, s_2)$ pour deux messages hachés en $z_1$ et $z_2$ avec le même $k$ :

1. Calcul du nonce $k$ :
   $$k = (z_1 - z_2) \cdot (s_1 - s_2)^{-1} \pmod n$$

2. Calcul de la clé privée $d$ :
   $$d = (s_1 \cdot k - z_1) \cdot r^{-1} \pmod n$$

---

## 💻 Étape 3 : Script d'Exploitation (`solve.py`)

Voici le script Python automatisant l'extraction de la clé à l'aide de la bibliothèque `ecdsa` :

```python
import base64
import json
from ecdsa import SECP256k1, SigningKey
from ecdsa.numbertheory import inverse_mod
from hashlib import sha256

# 1. Charger le fichier d'export JSON
with open("signing-export.json") as f:
    data = json.load(f)

# 2. Isoler les deux enregistrements vulnérables (R-6103 et R-6107)
recs = data["records"]
rec1 = next(r for r in recs if r["record_id"] == "R-6103")
rec2 = next(r for r in recs if r["record_id"] == "R-6107")

# 3. Extraire r et s depuis les chaînes hexadécimales
sig1_bytes = bytes.fromhex(rec1["signature_rs_hex"])
sig2_bytes = bytes.fromhex(rec2["signature_rs_hex"])

r1 = int.from_bytes(sig1_bytes[:32], "big")
s1 = int.from_bytes(sig1_bytes[32:], "big")
s2 = int.from_bytes(sig2_bytes[32:], "big")

# 4. Décoder les messages base64 et calculer leurs hachages SHA-256 (z1, z2)
m1_raw = base64.b64decode(rec1["message_b64"])
m2_raw = base64.b64decode(rec2["message_b64"])

z1 = int.from_bytes(sha256(m1_raw).digest(), "big")
z2 = int.from_bytes(sha256(m2_raw).digest(), "big")

# 5. Ordre de la courbe secp256k1
n = SECP256k1.order

# 6. Calculer k et la clé privée d
k = (z1 - z2) * inverse_mod(s1 - s2, n) % n
privkey_int = (s1 * k - z1) * inverse_mod(r1, n) % n

# 7. Afficher le résultat au format hexadécimal (64 caractères)
private_key_hex = f"{privkey_int:064x}"
print(f"[+] Clé privée (scalaire) : {private_key_hex}")

# Validation de la clé publique correspondante
sk = SigningKey.from_secret_exponent(privkey_int, curve=SECP256k1)
vk = sk.get_verifying_key()
print(f"[+] Vérification X : {vk.pubkey.point.x():064x}")
