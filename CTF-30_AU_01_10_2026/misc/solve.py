with open("forgotten_secrets.bin", "rb") as f:
    data = f.read()

# Le préfixe en clair que l'on cherche (ou sa forme XORée)
# hiCTF en ASCII : [0x68, 0x69, 0x43, 0x54, 0x46]
for key in range(1, 256):
  decrypted = bytes([b ^ key for b in data])
  if b"hiCTF" in decrypted or b"hictf" in decrypted:
    print(f"[*] Trouvé avec la clé XOR : {key} (0x{key:02x})")
    # Afficher un extrait autour du flag
    idx = decrypted.lower().find(b"hictf")
    print(decrypted[max(0, idx - 20) : idx + 50])
    break
