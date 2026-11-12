# Write-up : Watch List Audit (CSCTF)

## Overview

- **Category:** Misc / Data Analysis / Reverse Engineering
- **Flag:** `CSCTF{114ca27d8c3e02e5ec872dd02b83707cae245e2f07dadaa622867cf9b3894287}`

---

## Scenario & Objective

An adversary altered the scoring rules of a relief-dispatch screening service to delay evacuation supplies and slip convoys past a watch list.

We were provided with:
1. `history.csv`: 500 chronological observations ($f_0, \dots, f_9 \to \text{score}$) covering a single system deployment rule change.
2. `probes.csv`: 32 new inputs ($f_0, \dots, f_9$) to score using the updated rule.
3. `README.txt`: Instructions detailing the model structure, quantization, and flag formatting.

The goal was to:
1. Identify the exact point in the history where the scoring model changed.
2. Reconstruct the linear model coefficients for the latest deployment phase.
3. Predict the score for the 32 audit probes.
4. Quantize the scores using $q = \lfloor 1000 \cdot \text{score} + 0.5 \rfloor$.
5. Format the quantized outputs as ASCII integers separated by LF (`\n`) and submit `CSCTF{sha256_hash}`.

---

## Analysis & Methodology

### 1. Model Structure
According to the challenge specification:
$$\text{score} = \text{intercept} + \sum_{j=0}^{9} w_j \cdot f_j$$

This is a **Multiple Linear Regression** problem without noise. Since exactly one rule change occurred in the historical dataset, the problem translates to finding a **single changepoint** $k \in (15, 485)$ that splits the dataset into two distinct linear regimes:
- Regime 1: Rows $0 \dots k-1$
- Regime 2: Rows $k \dots 499$

### 2. Changepoint Detection
By performing an exhaustive search over all possible cut points $k$, we fit two linear regression models for each partition using Ordinary Least Squares (OLS) and sum their Residual Sum of Squares (RSS / SSE):

$$\text{SSE}_{\text{total}}(k) = \text{SSE}(0..k-1) + \text{SSE}(k..499)$$

The optimal split point corresponding to the minimum sum of squared errors was identified at **index 209** (row 210 in 1-based indexing).

### 3. Parameter Fitting & Inference
Using observations from index 209 to 499 ($X_{\text{latest}}$ and $y_{\text{latest}}$):
1. Solved for $\beta_{\text{latest}} = [w_0, w_1, \dots, w_9, \text{intercept}]$ using standard linear algebra / least squares (`np.linalg.lstsq`).
2. Evaluated the 32 rows of `probes.csv` against $\beta_{\text{latest}}$.

### 4. Quantization & Hashing
For each predicted float score:
$$q_i = \lfloor 1000 \cdot \text{score}_i + 0.5 \rfloor$$

Each integer $q_i$ was serialized into ASCII bytes followed by an ASCII LF (`0x0A`). The SHA-256 digest of this byte sequence produced the required flag payload.

---

## Solution Code

```python
import hashlib
import numpy as np
import pandas as pd

# Load datasets
history_df = pd.read_csv('history.csv')
probes_df = pd.read_csv('probes.csv')

X_hist = history_df.loc[:, [f'f{i}' for i in range(10)]].values
y_hist = history_df['score'].values
X_probes = probes_df.loc[:, [f'f{i}' for i in range(10)]].values

n_samples = len(X_hist)

# Search for the optimal changepoint
best_split = -1
min_sse = float('inf')

for split in range(15, n_samples - 15):
  X1, y1 = X_hist[:split], y_hist[:split]
  X2, y2 = X_hist[split:], y_hist[split:]

  X1_b = np.hstack([np.ones((X1.shape[0], 1)), X1])
  beta1, _, _, _ = np.linalg.lstsq(X1_b, y1, rcond=None)
  sse1 = np.sum((X1_b @ beta1 - y1) ** 2)

  X2_b = np.hstack([np.ones((X2.shape[0], 1)), X2])
  beta2, _, _, _ = np.linalg.lstsq(X2_b, y2, rcond=None)
  sse2 = np.sum((X2_b @ beta2 - y2) ** 2)

  total_sse = sse1 + sse2
  if total_sse < min_sse:
    min_sse = total_sse
    best_split = split

# Fit the latest regime (split to end)
X_latest = X_hist[best_split:]
y_latest = y_hist[best_split:]
X_latest_b = np.hstack([np.ones((X_latest.shape[0], 1)), X_latest])
beta_latest, _, _, _ = np.linalg.lstsq(X_latest_b, y_latest, rcond=None)

# Predict probe scores
X_probes_b = np.hstack([np.ones((X_probes.shape[0], 1)), X_probes])
scores = X_probes_b @ beta_latest

# Quantize scores
q_values = np.floor(1000 * scores + 0.5).astype(np.int64)

# Format payload
byte_stream = b''
for q in q_values:
  byte_stream += f'{q}\n'.encode('ascii')

# Compute SHA-256 and output flag
sha256_digest = hashlib.sha256(byte_stream).hexdigest()
print(f'CSCTF{{{sha256_digest}}}')
```

---

## Results Summary

- **Detected Changepoint:** Index 209
- **SHA-256 Hash:** `114ca27d8c3e02e5ec872dd02b83707cae245e2f07dadaa622867cf9b3894287`
- **Flag:** `CSCTF{114ca27d8c3e02e5ec872dd02b83707cae245e2f07dadaa622867cf9b3894287}`
