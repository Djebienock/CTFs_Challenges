import base64
import mmh3

# Remplacez par le chemin exact vers le favicon trouvé localement
chemin_favicon = 'favicon.ico'

try:
  with open(chemin_favicon, 'rb') as f:
    favicon_bytes = f.read()

  # Encodage Base64 au format Shodan
  b64_encoded = base64.encodebytes(favicon_bytes)

  # Calcul du MurmurHash3 signé
  favicon_hash = mmh3.hash(b64_encoded)

  print(f'[+] Favicon chargé depuis : {chemin_favicon}')
  print(f'[+] Hash calculé avec succès : {favicon_hash}')
  print(f'🏁 FLAG : CSCTF{{{favicon_hash}}}')

except FileNotFoundError:
  print(
      '[-] Fichier favicon.ico introuvable. Cherchez bien dans les dossiers du'
      ' challenge !'
  )
