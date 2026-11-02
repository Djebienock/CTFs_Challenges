# 🧩 Cipher Cascade - Write-up

Write-up pour le challenge de cryptographie **"Cipher Cascade"** (Blue Team Labs / CTF).

## 📋 Description du défi
Une transmission interceptée d'un opérateur véreux a été encodée à l'aide de plusieurs couches de chiffrement imbriquées les unes dans les autres. L'objectif était de remonter la chaîne pour révéler le flag caché.

* **Format du Flag :** `hiCTF{...}`
* **Couches appliquées (de l'extérieur vers l'intérieur) :** `Reverse` $\rightarrow$ `Base64` $\rightarrow$ `Hex` $\rightarrow$ `ROT13`

---

## 🔍 Analyse & Résolution

Puisque les couches ont été appliquées de l'extérieur vers l'intérieur, il suffit d'appliquer les opérations inverses dans l'ordre chronologique inverse :

1. **Inverser la chaîne (`Reverse`) :** Le message commençait par `=` (ce qui indique un padding Base64 inversé).
2. **Décoder le Base64 (`Base64 Decode`) :** Transformation du texte en une chaîne hexadécimale brute.
3. **Convertir l'Hexadécimal (`Hex to Text`) :** Conversion des octets en caractères lisibles.
4. **Déchiffrer ROT13 (`Shift 13`) :** La dernière couche correspondait à un chiffrement de César avec un décalage de 13.

---

## 💻 Script de Résolution (`solve.py`)

Voici le script Python utilisé pour automatiser le décodage et trouver le flag :

```python
import base64

# Chaîne encodée initiale
encoded = "=Q2NxcTM2EzMhZTM2gjNmVTN2MzMjZDNzkzNmVzY2YmNmVTN2MzMjZDNzkzNidzM1cDNwUjN3UzN"

# 1. Inverser la chaîne (Reverse)
reversed_str = encoded[::-1]

# 2. Décoder le Base64
decoded_b64 = base64.b64decode(reversed_str)

# 3. Convertir l'Hexadécimal en texte
text = bytes.fromhex(decoded_b64.decode('utf-8')).decode('utf-8')

# 4. Fonction pour appliquer un décalage César / ROT13
def caesar(s, shift):
    res = ""
    for c in s:
        if 'a' <= c <= 'z':
            res += chr((ord(c) - ord('a') - shift) % 26 + ord('a'))
        elif 'A' <= c <= 'Z':
            res += chr((ord(c) - ord('A') - shift) % 26 + ord('A'))
        else:
            res += c
    return res

# Appliquer le décalage de 13 (ROT13)
flag = caesar(text, 13)
print("Flag final :", flag)
