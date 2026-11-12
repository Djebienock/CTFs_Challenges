import re

with open("radar-silence.pcapng", "rb") as f:
    data = f.read()

# Recherche de tous les sous-domaines ou requêtes textuelles liées à svc-telemetry ou airnet.example
queries = re.findall(rb"([a-z0-9\-]+\.[a-z0-9\-]+\.svc-telemetry\.example)", data)
print("Requêtes DNS de télémétrie trouvées :")
for q in set(queries):
    print(q.decode('utf-8'))

# Recherche générale de chaînes de caractères ASCII imprimables de taille variable
print("\nToutes les chaînes textuelles significatives :")
strings = re.findall(rb"[a-zA-Z0-9_\-\.]{10,}", data)
for s in set(strings):
    decoded = s.decode('utf-8', errors='ignore')
    if "update" in decoded or "rdr37" in decoded or "telemetry" in decoded:
        print(decoded)
