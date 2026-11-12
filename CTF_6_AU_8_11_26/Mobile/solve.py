import base64
from Crypto.Cipher import AES
from hashlib import sha256

ciphertext_b64 = "5oQUos5iza6li4FHm+nyC2yzGTGaAhTT7DHZLsCW3khsXZn3fzyUW7eZj+8ZMOeKW99f/ONroSPFdDxSni70Celag2Hvw4sYVFcXdqM/"
ciphertext_bytes = base64.b64decode(ciphertext_b64)
iv = ciphertext_bytes[:12]
encrypted_data = ciphertext_bytes[12:]

strA0 = "KJSC-1C28DC7E-RECOVERY"
card_code = "ZHUU-SANS-9XJN-QPCQ"
digits = "4972"

material = (strA0 + digits + card_code).encode('utf-8')
aes_key = sha256(material).digest()

cipher = AES.new(aes_key, AES.MODE_GCM, nonce=iv)
flag = cipher.decrypt(encrypted_data)

print("\n" + "="*50)
print(f"[+] CODE PIN : {digits}")
print(f"[+] FLAG : {flag.decode('utf-8', errors='ignore')}")
print("="*50 + "\n")
