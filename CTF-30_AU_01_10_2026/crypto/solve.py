import base64

encoded = "=Q2NxcTM2EzMhZTM2gjNmVTN2MzMjZDNzkzNmVzY2YmNmVTN2MzMjZDNzkzNidzM1cDNwUjN3UzN"

# 1. Reverse
reversed_str = encoded[::-1]

# 2. Base64
decoded_b64 = base64.b64decode(reversed_str)

# 3. Hex -> Texte
text = bytes.fromhex(decoded_b64.decode('utf-8')).decode('utf-8')

# 4. Tester les décalages (César / ROT) pour trouver le format hiCTF{}
def caesar(s, shift):
    res = ""
    for c in s:
        if 'a' <= c <= 'z':
            res += chr((ord(c) - ord('a') - shift) % 26 + ord('a'))
        elif 'A' <= c <= 'Z':
            res += chr((ord(c) - ord('A') - shift) % 26 + ord('A'))
        else:
            res += c
    return res

print("Texte brut :", text)
for i in range(1, 26):
    print(f"Shift {i}: {caesar(text, i)}")
