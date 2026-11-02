with open("state.dat", "rb") as f:
    state_data = f.read()

with open("flag.enc", "rb") as f:
    flag_data = f.read()

print(f"[*] Taille de state.dat : {len(state_data)} octets")
print(f"[*] Taille de flag.enc : {len(flag_data)} octets")

# Testons un XOR avec une clé d'un seul octet (de 0 à 255) pour voir si du texte lisible apparaît
print("\n--- Recherche d'un XOR mono-octet sur state.dat ---")
for key in range(256):
    decrypted = bytes([b ^ key for b in state_data])
    # On cherche si des mots clés python ou du texte clair apparaissent (ex: 'def ', 'import ', 'print')
    if b"def " in decrypted or b"import " in decrypted or b"hiCTF" in decrypted:
        print(f"[+] Trouvé avec la clé XOR: {key} (0x{key:02x})")
        print(decrypted[:200]) # Afficher les 200 premiers caractères
        break

# Testons aussi sur flag.enc
print("\n--- Recherche d'un XOR mono-octet sur flag.enc ---")
for key in range(256):
    decrypted = bytes([b ^ key for b in flag_data])
    if b"hiCTF" in decrypted:
        print(f"[+] FLAG TROUVÉ avec la clé {key} (0x{key:02x}) :")
        print(decrypted)
        break
