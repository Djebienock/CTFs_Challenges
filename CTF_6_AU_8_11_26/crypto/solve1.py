from ecdsa import SECP256k1, SigningKey
from hashlib import sha256
import base64

# Ta clé privée trouvée
privkey_hex = "3b5789e468dadf358d375bb08dcd19b977c5715364a709326b43a35b0d5eaab1"
sk = SigningKey.from_secret_exponent(int(privkey_hex, 16), curve=SECP256k1)

# Exemple : Message à signer (ajuste selon le besoin du CTF, ex: "flag" ou un ordre spécial)
message_str = '{"cargo":"admin override","destination":"main terminal","dispatch_id":"R-9999","issued_at":"2026-10-07T02:00:00Z","issuer":"Meridian Emergency Logistics"}'
message_bytes = message_str.encode('utf-8')

# Signature ECDSA (déterministe RFC 6979 ou classique selon ce que demande ton outil de vérification)
signature = sk.sign_deterministic(message_bytes, hashfunc=sha256)

# R et S (32 octets chacun)
r = signature[:32].hex()
s = signature[32:].hex()

print(f"[+] Message base64 : {base64.b64encode(message_bytes).decode()}")
print(f"[+] Signature r||s : {r}{s}")
