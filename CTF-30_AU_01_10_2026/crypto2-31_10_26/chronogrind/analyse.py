from collections import Counter

with open("state.dat", "rb") as f:
    data = f.read()

# Compter la fréquence des octets
counter = Counter(data)
print("--- 10 octets les plus fréquents dans state.dat ---")
for byte, count in counter.most_common(10):
    print(f"Octet: 0x{byte:02x} ({chr(byte) if 32 <= byte <= 126 else 'non-imprimable'}): {count} fois")
