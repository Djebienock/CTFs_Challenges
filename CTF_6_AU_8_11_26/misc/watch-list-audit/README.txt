Watch List Audit

These are constructed numerical exports for an invented relief-dispatch scoring service, not records from a real deployment. Reconstruct its latest scoring behavior for response audit; this does not prove the cause of the change or certify the rule as safe.

history.csv contains 500 chronological observations, oldest first, with columns f0,...,f9,score. probes.csv contains 32 new inputs, with columns f0,...,f9 in the same feature order. CSV is ASCII, comma-separated, with a header and CRLF record endings. Numbers are finite IEEE-754 binary64 values printed with roundtrippable precision.

Within a deployment, score = intercept + sum(weight[j] * feature[j]) for j=0,...,9. Exactly one deployment change occurred in this history. A deployment change may change coefficients. No measurement noise was added. The latest rule applies to all probes. No cut position or fitting-window length is supplied.

Compute one score per probe in its supplied row order. For each score, compute q = floor(1000 * score + 0.5), including negative scores. Serialize each q as a signed base-10 integer: a minus sign only for negatives, no plus sign, no leading zeros, and zero as 0. Append exactly one ASCII LF byte (0x0a) after EVERY integer, including the last. Do not use CRLF, spaces, commas or brackets in this response serialization.

SHA-256 the resulting ASCII bytes. Submit CSCTF{ followed by the lowercase 64-hex SHA-256 digest, then }. Do not hash the CSV, floating-point strings, or this README. Numerical libraries may differ in their last floating-point digits; the quantized integer vector is the comparison object.

Original numerical history: Terminal43, Operation Dawn. Adaptation: Marin Radu. The audit probes are ordinary independently constructed inputs, not encoded message characters. No training history, real product, incident acquisition or attacker attribution is claimed.
