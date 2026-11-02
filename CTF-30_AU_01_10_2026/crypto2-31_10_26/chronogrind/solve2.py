with open("state.dat", "rb") as f:
    state_data = f.read()

with open("flag.enc", "rb") as f:
    flag_data = f.read()

# Si le fichier commence par une signature claire, ex: "CGD1L" (5 octets)
# Supposons que les premiers octets correspondent à un en-tête connu ou du texte en clair.
# Essayons de retrouver une clé XOR potentielle en comparant les premiers octets avec une structure attendue.

# Affichons les 30 premiers octets en hexadécimal pour observer d'éventuels motifs
print("Hex de state.dat[:30]:", state_data[:30].hex())
print("Hex de flag.enc[:30]:", flag_data[:30].hex())
