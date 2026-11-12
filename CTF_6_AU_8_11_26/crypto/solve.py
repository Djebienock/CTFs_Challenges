import base64
import json
from ecdsa import SECP256k1, SigningKey
from ecdsa.curves import NIST256p
from ecdsa.numbertheory import inverse_mod
from hashlib import sha256

# Charger le fichier JSON
with open("signing-export.json") as f:
    data = json.load(f)

# Récupérer les deux enregistrements avec le même 'r' (R-6103 et R-6107)
# On peut aussi vérifier programmaticement quelles signatures partagent le même r.
recs = data["records"]
rec1 = next(r for r in recs if r["record_id"] == "R-6103")
rec2 = next(r for r in recs if r["record_id"] == "R-6107")

sig1_bytes = bytes.fromhex(rec1["signature_rs_hex"])
sig2_bytes = bytes.fromhex(sig2_bytes_hex := rec2["signature_rs_hex"])

r1 = int.from_bytes(sig1_bytes[:32], "big")
s1 = int.from_bytes(sig1_bytes[32:], "big")
s2 = int.from_bytes(sig2_bytes[32:], "big")

# Messages décodés depuis le Base64
m1_raw = base64.b64decode(rec1["message_b64"])
m2_raw = base64.b64decode(rec2["message_b64"])

# Hash SHA-256 des messages (utilisé par secp256k1 ECDSA)
z1 = int.from_bytes(sha256(m1_raw).digest(), "big")
z2 = int.from_bytes(sha256(m2_raw).digest(), "big")

# Ordre de la courbe secp256k1
n = SECP256k1.order

# Calcul du nonce k compromis :
# k = (z1 - z2) * inverse_mod(s1 - s2, n) % n
k = (z1 - z2) * inverse_mod(s1 - s2, n) % n

# Calcul de la clé privée d :
# d = (s1 * k - z1) * inverse_mod(r, n) % n
privkey_int = (s1 * k - z1) * inverse_mod(r1, n) % n

print(f"[+] Clé privée (hex) : {privkey_int:064x}")

# Optionnel : recréer l'objet SigningKey pour signer un message arbitraire ou valider
sk = SigningKey.from_secret_exponent(privkey_int, curve=SECP256k1)
vk = sk.get_verifying_key()
print(f"[+] Clé publique X vérifiée : {vk.pubkey.point.x():064x}")
