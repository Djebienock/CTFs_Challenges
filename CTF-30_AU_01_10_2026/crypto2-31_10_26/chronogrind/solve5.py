with open("state.dat", "rb") as f:
    state_data = f.read()

# Test 1: XOR avec 0x4c (car ' ' ^ 'l' = 0x4c)
key_candidate = 0x20 ^ 0x6c # 0x4c
decrypted_xor = bytes([b ^ key_candidate for b in state_data])

print("--- Résultat XOR avec 0x4c (alignement espace -> 'l') ---")
print(decrypted_xor[0x370:0x470]) # On regarde la zone où se trouve le texte obfusqué

# Test 2: Si c'est un décalage rotatif (César) où ' ' (32) devient 'l' (108), le shift est 108 - 32 = 76
shift = ord('l') - ord(' ')
decrypted_caesar = bytes([(b - shift) % 256 for b in state_data])

print("\n--- Résultat Décalage (César -76) ---")
print(decrypted_caesar[0x370:0x470])
