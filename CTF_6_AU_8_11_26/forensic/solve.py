ciphertext_hex = "7a6a7a6d7f4251505d664a525c4e664b5c5d5550575c44"
cipher_bytes = bytes.fromhex(ciphertext_hex)

# Le début attendu du flag
expected_prefix = b"CSCTF{"

print("[*] Recherche de la clé par correspondance directe du préfixe 'CSCTF{'...")

# Testons toutes les clés possibles de 4 octets dont les premiers octets XORés avec le début du ciphertext donnent "CSCTF{"
for key_int in range(0, 4294967296): # Espace total des entiers 32-bits (ou testons d'abord une plage intelligente)
    pass

# Plus simple : dériver directement la clé à partir des premiers octets du ciphertext et du préfixe attendu
# cipher[0] ^ key[0] = 'C'  ==> key[0] = cipher[0] ^ ord('C')
derived_key_bytes = bytearray()
for i in range(min(len(expected_prefix), len(cipher_bytes))):
    derived_key_bytes.append(cipher_bytes[i] ^ expected_prefix[i])

print(f"[*] Octets de clé déduits du préfixe : {derived_key_bytes}")

# Si la clé est répétitive (4 octets), testons cette clé déduite sur tout le message :
for endian in ['big', 'little']:
    try:
        if len(derived_key_bytes) >= 4:
            if endian == 'big':
                key_val = int.from_bytes(derived_key_bytes[:4], 'big')
            else:
                key_val = int.from_bytes(derived_key_bytes[:4], 'little')
                
            key_bytes = key_val.to_bytes(4, byteorder=endian)
            decrypted = bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(cipher_bytes))
            print(f"Essai avec la clé entière {key_val} ({endian}) -> {decrypted}")
            if decrypted.startswith(b"CSCTF{"):
                print(f"\n[+] SUCCÈS TOTAL ! FLAG : {decrypted.decode('utf-8')}")
                exit()
    except Exception as e:
        pass

# Testons également un force brute rapide sur les clés de 4 octets basées sur les deltas logiques ou un pattern de timestamp
print("[*] Recherche par force brute optimisée sur les entiers 32-bits...")
for k in range(0, 200000000, 1000): # Échantillonnage ou test complet si besoin
    for endian in ['big', 'little']:
        try:
            kb = k.to_bytes(4, byteorder=endian)
            if (cipher_bytes[0] ^ kb[0]) == ord('C') and (cipher_bytes[1] ^ kb[1]) == ord('S'):
                decrypted = bytes(b ^ kb[i % len(kb)] for i, b in enumerate(cipher_bytes))
                if decrypted.startswith(b"CSCTF{"):
                    print(f"\n[+] TROUVÉ ! Clé : {k} ({endian})")
                    print(f"[+] FLAG : {decrypted.decode('utf-8')}")
                    exit()
        except:
            continue
print("[-] Fin du test ciblé.")
