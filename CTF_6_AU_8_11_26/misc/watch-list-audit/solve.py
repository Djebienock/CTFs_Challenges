import hashlib
import numpy as np
import pandas as pd

# 1. Charger les données
history_df = pd.read_csv('history.csv')
probes_df = pd.read_csv('probes.csv')

X_hist = history_df.loc[:, [f'f{i}' for i in range(10)]].values
y_hist = history_df['score'].values
X_probes = probes_df.loc[:, [f'f{i}' for i in range(10)]].values

n_samples = len(X_hist)
print(f"Nombre d'observations historiques : {n_samples}")

# 2. Trouver le point de changement (changepoint) exact
# On teste tous les découpages possibles pour trouver celui qui minimise l'erreur résiduelle totale (SSE)
best_split = -1
min_sse = float('inf')

# On s'assure d'avoir au moins 11 échantillons de chaque côté pour estimer les 11 paramètres (10 poids + 1 intercept)
for split in range(15, n_samples - 15):
  # Premier régime : de 0 à split
  X1, y1 = X_hist[:split], y_hist[:split]
  # Second régime : de split à la fin
  X2, y2 = X_hist[split:], y_hist[split:]

  # Régression linéaire pour le régime 1 (en ajoutant une colonne de 1 pour l'intercept)
  X1_b = np.hstack([np.ones((X1.shape[0], 1)), X1])
  beta1, _, _, _ = np.linalg.lstsq(X1_b, y1, rcond=None)
  sse1 = np.sum((X1_b @ beta1 - y1) ** 2)

  # Régression linéaire pour le régime 2
  X2_b = np.hstack([np.ones((X2.shape[0], 1)), X2])
  beta2, _, _, _ = np.linalg.lstsq(X2_b, y2, rcond=None)
  sse2 = np.sum((X2_b @ beta2 - y2) ** 2)

  total_sse = sse1 + sse2
  if total_sse < min_sse:
    min_sse = total_sse
    best_split = split

print(
    f'Point de changement optimal détecté à l\'indice : {best_split}'
    f' (observation {best_split + 1})'
)

# 3. Recalculer les coefficients du dernier régime (le plus récent, appliqué aux probes)
X_latest = X_hist[best_split:]
y_latest = y_hist[best_split:]
X_latest_b = np.hstack([np.ones((X_latest.shape[0], 1)), X_latest])
beta_latest, _, _, _ = np.linalg.lstsq(X_latest_b, y_latest, rcond=None)

# 4. Calculer les scores pour les nouvelles sondes (probes)
X_probes_b = np.hstack([np.ones((X_probes.shape[0], 1)), X_probes])
scores = X_probes_b @ beta_latest

# 5. Quantifier selon les règles : q = floor(1000 * score + 0.5)
# Attention à la précision flottante, np.floor ou round() avec gestion précise
q_values = np.floor(1000 * scores + 0.5).astype(np.int64)

# 6. Sérialisation exacte selon les instructions de README.txt :
# - "Serialize each q as a signed base-10 integer: a minus sign only for negatives..."
# - "Append exactly one ASCII LF byte (0x0a) after EVERY integer, including the last."
# - "Do not use CRLF, spaces, commas or brackets in this response serialization."
byte_stream = b''
for q in q_values:
  line_str = f'{q}\n'
  byte_stream += line_str.encode('ascii')

# 7. Calcul du SHA-256
sha256_digest = hashlib.sha256(byte_stream).hexdigest()

# 8. Affichage du flag final
flag = f'CSCTF{{{sha256_digest}}}'
print('Flag final :')
print(flag)
