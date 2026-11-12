# 🏔️ Write-up CTF : Roof of Africa (Stéganographie)

Un write-up détaillé retraçant la résolution du challenge de stéganographie **Roof of Africa** (plateforme hiCTF / Blue Team Labs).

---

## 📌 1. Informations sur le Challenge

* **Nom de l'archive** : `roof-of-africa.zip`
* **Empreinte SHA-256** : `137a5a7ec2a314e1027a7a279d33e45cd0a95256f63b35cca2d3fb233c3209ed`
* **Format du Flag** : `hiCTF{...}`
* **Fichiers extraits** : `roof_of_africa.jpg`

---

## 🔍 2. Analyse de l'Énoncé et Énigme

### Énoncé :
> *"They say Africa's highest peak holds ancient secrets in its frozen glaciers. A photograph has been intercepted — but its true meaning is locked away, protected by the mountain's most famous number. Can you reach the summit and uncover what lies hidden?"*

### Analyse déductive :
1. **Sommet de l'Afrique** : Le point culminant du continent africain est le **Mont Kilimandjaro** (Tanzanie).
2. **Le nombre le plus célèbre** : Il s'agit de son altitude officielle en mètres :

$$
\text{Altitude du Kilimandjaro} = 5895 \text{ mètres}
$$

Ce nombre ($5895$) servira de mot de passe (*passphrase*) pour extraire la donnée cachée.

---

## 🛠️ 3. Outils Utilisés et Procédure Détaillée

### 1. Inspecter les métadonnées avec `exiftool`

#### 📖 À quoi sert `exiftool` ?
`exiftool` est un outil d'analyse en ligne de commande permettant de lire, écrire et modifier les métadonnées de nombreux formats de fichiers (images, audios, vidéos, PDF). En stéganographie et en analyse Blue Team / Forensic, il permet de détecter des informations confidentielles intégrées dans les champs d'en-tête (coordonnées GPS, auteur, commentaires cachés, dates).

#### 💻 Utilisation et sortie du terminal :
```bash
┌──(kali㉿kali)-[~/Downloads/blueteamlabs/steg]
└─$ exiftool roof_of_africa.jpg 
ExifTool Version Number         : 13.55
File Name                       : roof_of_africa.jpg
Directory                       : .
File Size                       : 625 kB
File Modification Date/Time     : 2026:10:15 08:48:52-04:00
File Access Date/Time           : 2026:10:31 09:01:22-04:00
File Inode Change Date/Time     : 2026:10:31 09:01:22-04:00
File Permissions                : -rw-rw-r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
Resolution Unit                 : None
X Resolution                    : 1
Y Resolution                    : 1
Image Width                     : 1600
Image Height                    : 1056
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:4:4 (1 1)
Image Size                      : 1600x1056
Megapixels                      : 1.7
```

**Diagnostic** : Les métadonnées EXIF sont standard et ne contiennent aucun flag en clair.

---

### 2. Examiner le contenu binaire avec `strings`

#### 📖 À quoi sert `strings` ?
`strings` extrait et affiche les chaînes de caractères lisibles (imprimables) d'au moins 4 caractères contenues dans un fichier binaire. Cela permet de repérer si un texte, une clé ou une signature de fichier a été concaténé directement à la fin du fichier image.

#### 💻 Utilisation et sortie du terminal :
```bash
┌──(kali㉿kali)-[~/Downloads/blueteamlabs/steg]
└─$ strings roof_of_africa.jpg 
JFIF
$3br
%&'()*456789:CDEFGHIJSTUVWXYZcdefghijstuvwxyz
        #3R
&'()*56789:CDEFGHIJSTUVWXYZcdefghijstuvwxyz
6p(3
41,<
N2=h
...
9`*@R
```

**Diagnostic** : Aucune chaîne de texte pertinente ni aucun flag n'apparaît en clair dans les données binaires. Cela confirme que le secret a été chiffré et caché via un algorithme de stéganographie.

---

### 3. Extraction de la charge utile avec `steghide`

#### 📖 À quoi sert `steghide` ?
`steghide` est un logiciel de stéganographie spécialisé dans le dissimule d'informations au sein de fichiers images (JPEG, BMP) ou audio (WAV, AU). Il offre un chiffrement algorithmique basé sur un mot de passe (passphrase).

#### Options de commande :
* `extract` : Demande à l'outil d'extraire les données enfouies.
* `-sf` (*stego file*) : Spécifie le fichier hôte contenant l'information secrète (`roof_of_africa.jpg`).
* `-p` (*passphrase*) : Fournit le mot de passe nécessaire pour déchiffrer les données (`5895`).

#### 💻 Utilisation et sortie du terminal :
```bash
┌──(kali㉿kali)-[~/Downloads/blueteamlabs/steg]
└─$ steghide extract -sf roof_of_africa.jpg -p 5895
wrote extracted data to "roof_flag_v2.txt".
```

---

### 4. Vérification et lecture du résultat (`ls` et `cat`)

#### 📖 À quoi servent `ls` et `cat` ?
* `ls` : Liste les fichiers du répertoire courant pour confirmer l'extraction.
* `cat` (*concatenate*) : Affiche le contenu d'un fichier texte dans le terminal.

#### 💻 Utilisation et sortie du terminal :
```bash
┌──(kali㉿kali)-[~/Downloads/blueteamlabs/steg]
└─$ ls
roof_flag_v2.txt  roof_of_africa.jpg  roof-of-africa.zip

┌──(kali㉿kali)-[~/Downloads/blueteamlabs/steg]
└─$ cat roof_flag_v2.txt
hiCTF{h4kun4_m4t4t4_m34ns_n0_w0rr13s}
```

---

## 🚩 4. Flag Final

```text
hiCTF{h4kun4_m4t4t4_m34ns_n0_w0rr13s}
```
