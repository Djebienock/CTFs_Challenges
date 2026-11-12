# Torven Ordnance - Release Signing Authority (Crypto)

## Description du challenge
Le service de signature de code de **Torven Ordnance** promeut l'image d'armement principale (`master-arming-image`) uniquement sur une signature ECDSA valide (`secp256k1`) d'un message exact, sans vouloir signer ce message pour nous. Cependant, le service publie des reçus de signature de release (`/receipts`).

---

## Vulnérabilité : Réutilisation du Nonce ($k$-reuse)
En inspectant les reçus disponibles via l'endpoint `/receipts`, on remarque que deux reçus (`ta-9.7.14` et `ta-9.7.15`) possèdent **exactement la même valeur de $r$** :
`6a2953084c3296a4a56e224b3c761359ddeb5a5de903ba72cb668e83d43c4ba3`

En ECDSA, si le générateur aléatoire $k$ est réutilisé pour deux messages différents ($z_1$ et $z_2$), il est mathématiquement possible de retrouver la clé privée $d$ du serveur ainsi que le nonce $k$ à l'aide des formules suivantes :

$$k \equiv (z_1 - z_2) \cdot (s_1 - s_2)^{-1} \pmod n$$
$$d \equiv (s_1 \cdot k - z_1) \cdot r^{-1} \pmod n$$

---

## Résolution étape par étape

1. **Récupération des données** : Téléchargement des reçus depuis l'API (`/receipts`).
2. **Extraction et calcul des hachages** : Conversion des messages hexadécimaux en entiers via la fonction de hachage spécifiée (`sha256-int-be-mod-n`).
3. **Récupération de la clé privée ($d$)** : Application de la formule de réutilisation de nonce.
4. **Signature du message maître** : Génération d'une signature valide pour le `master_message_hex` avec la clé retrouvée, tout en respectant la règle **low-s** ($s \le \lfloor n / 2 \rfloor$).
5. **Validation** : Envoi de la requête `POST /authorize` avec un format JSON strict et minifié.

---

## Script de résolution (`solve.py`)

```python
import hashlib
import json
import requests
from ecdsa.curves import SECP256k1

# Configuration et constantes
BASE_URL = "[http://w04.ctf.chronos-security.ro:32931](http://w04.ctf.chronos-security.ro:32931)"
N = SECP256k1.order

MASTER_MSG_HEX = (
    "544f5256454e2d415554485a2d56310a"
    "6f7065726174696f6e3d70726f6d6f74652d6d61737465722d61726d696e670a"
    "61727469666163743d6d61737465722d61726d696e672d696d6167650a"
)


def hash_to_int(msg_hex: str) -> int:
    msg_bytes = bytes.fromhex(msg_hex)
    digest = hashlib.sha256(msg_bytes).digest()
    return int.from_bytes(digest, byteorder="big") % N


# 1. Récupération des reçus
resp = requests.get(f"{BASE_URL}/receipts")
data = resp.json()
receipts = data["receipts"]

signatures = []
for item in receipts:
    msg_hex = item["message_hex"]
    r = int(item["r"], 16)
    s = int(item["s"], 16)
    z = hash_to_int(msg_hex)
    signatures.append({"r": r, "s": s, "z": z})

# 2. Recherche de réutilisation de nonce (même r)
recovered_d = None

for i in range(len(signatures)):
    for j in range(i + 1, len(signatures)):
        sig1 = signatures[i]
        sig2 = signatures[j]

        if sig1["r"] == sig2["r"]:
            print(f"[+] Réutilisation de nonce trouvée entre les reçus !")
            r = sig1["r"]
            s1, z1 = sig1["s"], sig1["z"]
            s2, z2 = sig2["s"], sig2["z"]

            # k = (z1 - z2) * inv(s1 - s2) mod n
            num_k = (z1 - z2) % N
            den_k = (s1 - s2) % N
            k = (num_k * pow(den_k, -1, N)) % N

            # d = (s1 * k - z1) * inv(r) mod n
            num_d = (s1 * k - z1) % N
            d = (num_d * pow(r, -1, N)) % N

            recovered_d = d
            print(f"[+] Clé privée d récupérée : {hex(d)}")
            break
    if recovered_d:
        break

if not recovered_d:
    print("[-] Aucun nonce réutilisé trouvé.")
    exit(1)

# 3. Signature du message maître
z_master = hash_to_int(MASTER_MSG_HEX)
k_new = 1337
r_point = k_new * SECP256k1.generator
r_new = r_point.x() % N
s_new = (pow(k_new, -1, N) * (z_master + r_new * recovered_d)) % N

# Application de la règle low-s
if s_new > N // 2:
    s_new = N - s_new

r_hex = f"{r_new:064x}"
s_hex = f"{s_new:064x}"

# 4. Envoi de la requête POST vers /authorize
payload = json.dumps(
    {"message_hex": MASTER_MSG_HEX, "r": r_hex, "s": s_hex},
    separators=(",", ":"),
)

headers = {"Content-Type": "application/json"}
res = requests.post(f"{BASE_URL}/authorize", data=payload, headers=headers)

print("[+] Réponse du serveur :")
print(res.text)
