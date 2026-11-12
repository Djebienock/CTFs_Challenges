# Write-up : VaultKeeper (CTF Mobile)

## 📌 Vue d'ensemble du Challenge
- **Fible cible** : `vaultkeeper.apk`
- **Objectif** : Extraire le flag caché sous le format `CSCTF{...}` par **analyse statique**, sans utiliser d'émulateur ni exécuter l'application dynamiquement.
- **Flag obtenu** : `CSCTF{intent_uri_and_a_broadcast_unlock_the_vault}`

---

## 🔍 Étape 1 : Décompilation et Analyse Statique initiale
Pour comprendre le fonctionnement de l'application, l'APK a été décompilé à l'aide de **JADX** afin d'inspecter le code Java/Kotlin et les fichiers de ressources.

1. **Extraction des ressources (`res/values/strings.xml`)** :
   - Recherche du texte chiffré cible (`flag_ciphertext_b64`) :
     ```xml
     <string name="flag_ciphertext_b64">5oQUos5iza6li4FHm+nyC2yzGTGaAhTT7DHZLsCW3khsXZn3fzyUW7eZj+8ZMOeKW99f/ONroSPFdDxSni70Celag2Hvw4sYVFcXdqM/</string>
     ```
   - Recherche de la session par défaut (`archive_session`) :
     ```xml
     <string name="archive_session">VK-7F42</string>
     ```

2. **Analyse de la logique de déchiffrement (`MainActivity.java`)** :
   - L'application décode le texte chiffré en Base64.
   - Les **12 premiers octets** du texte décodé correspondent au vecteur d'initialisation (**IV**) pour le chiffrement **AES-GCM**.
   - Le reste du payload correspond aux données chiffrées.

---

## 🔑 Étape 2 : Analyse de la Dérivation de Clé (Key Derivation)
En inspectant la méthode de déchiffrement dans `MainActivity.java`, on découvre que la clé AES de 256 bits est générée via un hachage **SHA-256** d'une concaténation de trois éléments :

1. **`strA0`** (Jeton de diagnostic de l'application) :
   - Généré dynamiquement par la méthode `A.c.a0(Context context)`.
   - Code analysé dans `A/c.java` : Il calcule le SHA-256 de la signature du certificat de l'APK (`META-INF/*.RSA`), en extrait les 8 premiers caractères en hexadécimal majuscule, et les encadre.
   - Commande pour extraire le digest SHA-256 du certificat :
     ```bash
     keytool -printcert -file META-INF/*.RSA
     ```
   - Résultat obtenu : Signature SHA-256 `1c28dc7e5ab079ffa0f014a0fefd11c7bf673e5d0d912c4c80ebd210818894d6` -> `strA0` = `KJSC-1C28DC7E-RECOVERY`.

2. **`archive_digits_cache`** (Code PIN à 4 chiffres) :
   - Stocké dans les `SharedPreferences` de l'application ou saisi par l'utilisateur (valeur comprise entre `0000` et `9999`).

3. **La carte d'autorisation / Jeton de session (`card_code`)** :
   - Récupéré depuis l'interface ou les données de contexte de l'archive : `ZHUU-SANS-9XJN-QPCQ`.

---

## 🛠️ Étape 3 : Résolution et Brut-Force Local (`solve.py`)
Puisque le code PIN n'a que 10 000 combinaisons possibles, un script Python a été rédigé pour simuler la dérivation de clé par SHA-256 et tenter le déchiffrement AES-GCM en boucle hors ligne.

### Script de résolution (`solve.py`) :
```python
import base64
from Crypto.Cipher import AES
from hashlib import sha256

# Données extraites de l'APK
ciphertext_b64 = "5oQUos5iza6li4FHm+nyC2yzGTGaAhTT7DHZLsCW3khsXZn3fzyUW7eZj+8ZMOeKW99f/ONroSPFdDxSni70Celag2Hvw4sYVFcXdqM/"
ciphertext_bytes = base64.b64decode(ciphertext_b64)
iv = ciphertext_bytes[:12]
encrypted_data = ciphertext_bytes[12:]

strA0 = "KJSC-1C28DC7E-RECOVERY"
card_code = "ZHUU-SANS-9XJN-QPCQ"

print("[*] Lancement du brut-force du code PIN...")
for i in range(10000):
    digits = f"{i:04d}"
    
    # Concaténation exacte identifiée dans MainActivity.java
    material = (strA0 + digits + card_code).encode('utf-8')
    aes_key = sha256(material).digest()
    
    try:
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=iv)
        flag = cipher.decrypt(encrypted_data)
        if b"CSCTF{" in flag:
            print(f"[+] Code PIN trouvé : {digits}")
            print(f"[+] FLAG : {flag.decode('utf-8', errors='ignore')}")
            break
    except Exception:
        continue
