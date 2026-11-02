# Writeups: CTF Steganography Challenges (hiCTF / BlueTeamLabs)

Ce dépôt contient les writeups détaillés de la résolution de deux challenges de stéganographie sur le thème de l'Afrique.


## 🏝️ Challenge 2 : Zanzibar Whisper

* **Fichier initial :** `zanzibar-whisper.zip`

* **SHA-256 :** `48aedaaf1a363d859ceaece068354394edd6a8ff1ea7245af3fde395aa749a67`

* **Flag :** `hiCTF{sp1c3_1sl4nd_s3cr3ts}`

### Étape par étape :

1. **Inspection des métadonnées avec `exiftool` :**

   ```
   exiftool zanzibar_whisper.jpg
   
   ```

2. **Vérification LSB et gestion des erreurs (`zsteg`) :**

   ```
   zsteg zanzibar_whisper.jpg
   
   ```

   * **À quoi sert `zsteg` ?** `zsteg` permet de détecter automatiquement les données cachées par stéganographie LSB (Least Significant Bit) sur les canaux de couleur.

   * *Note d'erreur :* L'exécution renvoie une erreur car `zsteg` fonctionne exclusivement sur des formats d'images sans perte (**PNG/BMP**). Son échec confirme que le format JPEG requiert une méthode d'extraction différente.

3. **Vérification de fichiers concaténés avec `binwalk` :**

   ```
   binwalk zanzibar_whisper.jpg
   
   ```

   * **À quoi sert `binwalk` ?** `binwalk` analyse les signatures binaires ("magic bytes") à l'intérieur d'un fichier pour détecter si d'autres fichiers (comme des archives ZIP ou des données texte) ont été ajoutés à la fin de l'image.

4. **Attaque et extraction automatisée avec `stegseek` :**
   Puisque l'image contient des données cachées via `steghide` sans mot de passe évident, nous menons une attaque automatisée par dictionnaire :

   ```
   stegseek zanzibar_whisper.jpg /usr/share/wordlists/rockyou.txt
   
   ```

   * **À quoi sert `stegseek` ?** `stegseek` est une version optimisée et extrêmement rapide de casser de mots de passe pour `steghide`. Il teste des millions de mots de passe de la liste `rockyou.txt` en quelques secondes et extrait automatiquement le fichier (dans ce cas, une passphrase vide `""` a été identifiée).

5. **Récupération du Flag :**

   ```
   cat zanzibar_whisper.jpg.out
   
   ```
