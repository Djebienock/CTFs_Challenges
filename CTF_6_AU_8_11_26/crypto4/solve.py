import cbor2
import hashlib

with open("key-unit-journal.cbor", "rb") as f:
    journal = cbor2.loads(f.read())

traffic = journal["traffic"]
register = journal["register"]

ciphertext = None
for pkt in traffic:
    if pkt["tx"] == 155:
        ciphertext = pkt["sealed"]
        break

# Testons l'utilisation de différents sous-ensembles de mots du registre 
# combinés avec tous les compteurs de départ possibles pour le SHA-256
found = False

for start_idx in range(len(register) - 8):
    key_words = register[start_idx : start_idx + 8]
    key_bytes = b"".join(w.to_bytes(4, 'big') for w in key_words)
    
    for start_i in range(10):
        ks = b""
        for i in range(start_i, start_i + 3):
            ks += hashlib.sha256(key_bytes + i.to_bytes(4, 'big')).digest()
            
        plaintext = bytes(c ^ k for c, k in zip(ciphertext, ks[:len(ciphertext)]))
        
        if b"CSCTF{" in plaintext:
            print(f"\n[+] FLAG TROUVÉ à l'index de registre {start_idx} avec start_i={start_i} !")
            print("Message / Flag complet :")
            print(plaintext.decode('utf-8', errors='ignore'))
            found = True
            break
    if found:
        break

if not found:
    print("Recherche par dictionnaire sur les hachages des premiers mots...")
