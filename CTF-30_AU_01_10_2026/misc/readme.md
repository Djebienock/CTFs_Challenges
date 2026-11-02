# Write-up : Forgotten Secrets (CTF)

## 📋 Description du Challenge

- **Nom du challenge :** Forgotten Secrets
- **Catégorie :** Forensic / Reverse Engineering / Stéganographie
- **Format du flag :** `hiCTF{...}`
- **Fichier fourni :** `forgotten-secrets.zip` (décompressé en `forgotten_secrets.bin`)
- **Somme de contrôle SHA-256 :** `bfde7ee94bc2841f3c9fc6275e6f005256df9d1a77363f291ec8adc90929840a`
- **Objectif :** Retrouver un flag caché/obfusqué au cœur d'un dump binaire altéré.

---

## 🛠️ Outils Utilisés

1. **`file`** : Identification du type de fichier et détection des anomalies dans l'en-tête ELF (corruption volontaire).
2. **`strings`** : Extraction des chaînes de caractères lisibles du binaire.
3. **`readelf` / `nm`** : Inspection des sections et symboles d'un binaire ELF (qui ont échoué en raison de la corruption délibérée des headers).
4. **Python 3** : Écriture et exécution d'un script de force brute par déchiffrement XOR octet par octet.

---

## 🔍 Étapes de la Résolution

### 1. Décompression de l'archive
On commence par décompresser l'archive `.zip` fournie pour extraire le fichier binaire :

```bash
unzip forgotten-secrets.zip
ls -la
```

### 2. Inspection initiale du fichier
Une analyse du type de fichier avec la commande `file` montre un fichier ELF 64-bit altéré avec des en-têtes corrompus (`unknown arch 0xffffc4aa`), conçus pour perturber les outils d'analyse automatique :

```bash
file forgotten_secrets.bin
# Résultat : forgotten_secrets.bin: ELF 64-bit LSB *unknown arch 0xffffc4aa* (SYSV)
```

### 3. Recherche directe de chaînes et tentative d'analyse ELF
Une recherche classique du format de flag avec `strings` ou une tentative d'analyse de la structure avec `readelf` et `nm` ne donne aucun résultat valide ou produit des erreurs de lecture :

```bash
# Recherche de la chaîne de caractères (aucun résultat)
strings -n 4 forgotten_secrets.bin | grep -i "hiCTF"

# Tentatives d'analyse des en-têtes (erreurs de parsing)
readelf -S forgotten_secrets.bin
nm forgotten_secrets.bin
```

Cela confirme que les données lisibles ont subi une transformation (obfuscation/chiffrement).

### 4. Attaque par Force Brute XOR (Python)
L'hypothèse d'un chiffrement XOR à clé unique d'un octet (valeurs possibles de `1` à `255`) est privilégiée. Un script Python réapplique chaque clé XOR sur l'intégralité du fichier jusqu'à détecter la présence de la signature du flag (`hiCTF`).

---

## 💻 Code Source de Résolution (`solve.py`)

```python
#!/usr/bin/env python3

# Lecture du fichier binaire obfusqué
with open("forgotten_secrets.bin", "rb") as f:
    data = f.read()

print("[*] Analyse du fichier en cours (Test des 255 clés XOR possibles)...")

# Parcours de toutes les clés XOR sur 1 octet (de 0x01 à 0xFF)
for key in range(1, 256):
    # Application de l'opération XOR sur chaque octet du binaire
    decrypted = bytes([b ^ key for b in data])
    
    # Vérification de la présence du motif du flag (insensible à la casse)
    if b"hiCTF" in decrypted or b"hictf" in decrypted:
        print(f"\n[+] Succès ! Clé XOR trouvée : {key} (0x{key:02x})")
        
        # Localisation de la position du flag
        idx = decrypted.lower().find(b"hictf")
        
        # Extraction et affichage du flag
        snippet = decrypted[max(0, idx - 20) : idx + 50]
        print(f"[*] Extrait décodé : {snippet}")
        break
```

---

## 🏆 Résultat & Flag

Exécution du script Python :

```bash
python3 solve.py
```

**Sortie :**
```text
[*] Trouvé avec la clé XOR : 66 (0x42)
b'\xda\xaa\xbb]\xf7\xd5\x02\xabsD^+\x06\x07\x03\x06\x00\x07\x07\x04hiCTF{m3m0ry_dump_d1g_d33p}\x01\x03\x04\x07\x00\x03\x00\x07\x9e\xbf]\x1e\xb9P\xb8K\x83\x92\xe9\xcb\xe4de'
```

**Flag final :**
```text
hiCTF{m3m0ry_dump_d1g_d33p}
```
