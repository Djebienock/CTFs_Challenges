import urllib.request
import json
import hashpumpy
import binascii

sig = "217521e9ddefffa11fb045d9f6a9a145ccba47b6625ee5cc48743a9ba3662848"
original_message = b"station=CORRIDOR-3&cmd=STATUS&ts=1764182323&nonce=cf45949e"
addition = "&cmd=DISPATCH"
url = "http://w02.ctf.chronos-security.ro:32808/api/command"

for kl in range(1, 65):
    try:
        new_sig, new_msg_bytes = hashpumpy.hashpump(sig, original_message, addition, kl)
        new_message_hex = binascii.hexlify(new_msg_bytes).decode()
        
        payload = {"message_hex": new_message_hex, "sig": new_sig}
        data = json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(url, data=data, headers={'Content-Type': 'application/json'})
        
        with urllib.request.urlopen(req) as response:
            print(f"[+] Succès avec key_length = {kl} !")
            print("Response:", response.read().decode('utf-8'))
            break
    except urllib.error.HTTPError as e:
        # Ignore les erreurs 400 et continue la recherche
        continue
