with open("state.dat", "rb") as f:
    state_data = f.read()

print("--- Test de décalages (Cesar/Shift) sur state.dat ---")
for shift in range(1, 256):
    shifted = bytes([(b - shift) % 256 for b in state_data])
    # Cherchons si des mots Python ou des mots courants apparaissent
    if b"def " in shifted or b"import " in shifted or b"print" in shifted or b"flag" in shifted:
        print(f"[+] Trouvé avec le décalage (soustraction) : {shift}")
        print(shifted[:300])
        break

    shifted_add = bytes([(b + shift) % 256 for b in state_data])
    if b"def " in shifted_add or b"import " in shifted_add or b"print" in shifted_add or b"flag" in shifted_add:
        print(f"[+] Trouvé avec le décalage (addition) : {shift}")
        print(shifted_add[:300])
        break
