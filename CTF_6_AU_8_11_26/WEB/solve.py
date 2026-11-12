import re
import urllib.parse

log_file = "attacker_requests.log"

# Dictionnaire pour stocker le caractère trouvé à chaque position
flag_chars = {}

with open(log_file, "r") as f:
    for line in f:
        # Recherche de l'expression SUBSTR(token, POS, 1)='CHAR' ou similaire
        # Le pattern capture la position et le caractère testé
        match = re.search(r'SUBSTR\(token,\s*(\d+),\s*1\)\s*=\s*\'([^\']+)\'', line)
        if match:
            pos = int(match.group(1))
            char = match.group(1) # ou le groupe 2 pour le caractère
            char = match.group(2)
            
            # Recherche également du temps de réponse (rt=...) à la fin de la ligne nginx combined
            rt_match = re.search(r'rt=([\d.]+)', line)
            if rt_match:
                rt = float(rt_match.group(1))
                
                # Si le temps de réponse est supérieur à 1.5s, c'est que le SLEEP(2) s'est déclenché !
                if rt > 1.5:
                    flag_chars[pos] = urllib.parse.unquote(char)

# Reconstruction de la chaîne triée par position
sorted_positions = sorted(flag_chars.keys())
secret = "".join([flag_chars[p] for p in sorted_positions])

print(f"Secret récupéré : {secret}")
