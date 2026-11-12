with open("state.dat", "rb") as f:
    state_data = f.read()

# Testons si une clé XOR répétée apparaît sur les premiers octets si on suppose un texte clair
# Par exemple, si les 4 premiers octets sont censés être "CGD1" ou autre chose.
known_header = b"CGD1"
key_guess = bytes([state_data[i] ^ known_header[i] for i in range(len(known_header))])
print(f"[*] Clé potentielle basée sur '{known_header.decode()}': {key_guess}")

# Appliquons cette clé potentielle (si elle fait 4 octets) sur tout le fichier pour voir ce que ça donne
def xor_repeating(data, key):
    return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])

decrypted = xor_repeating(state_data, key_guess)
print("\n--- Essai de déchiffrement de state.dat avec la clé répétée ---")
print(decrypted[:300])
