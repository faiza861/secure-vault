# Anomaly detector evaluation

Reproduce with:

```text
python -m securevault.monitor.train
python scripts/evaluate_detector.py
```

Setup: Isolation Forest (100 trees, 128 samples per tree, 1% contamination) trained on 4000 simulated normal
windows (seed 42). Evaluated on 2000 fresh normal windows and 300 windows of each attack type (seed 2026),
none seen during training.

| Window type | Rules only | AI only | Hybrid |
|---|---|---|---|
| Normal (false alarms) | 0.0% | 0.5% | 0.5% |
| Bulk download | 100% | 100% | 100% |
| Brute-force unlocks | 100% | 31.7% | 100% |
| Night access | 100% | 11.7% | 100% |
| Moderate scraping | 0.0% | 100% | 100% |
| **Overall recall** | 75.0% | 60.8% | **100%** |

## What this shows

* The two layers are **complementary**. Rules are exact on the patterns someone thought of in advance. The model
  is weak on those (it has no notion of "failed unlock" being sinister) but catches *moderate scraping*, which
  stays under every fixed threshold.
* Together they flag every simulated attack with a 0.5% false-alarm rate.

## Honest caveats

* **The data is simulated, and so are the attacks.** I designed "moderate scraping" to sit below the rule
  thresholds, which makes the hybrid look good by construction. A real evaluation needs real usage logs and
  attacks written by someone other than the author of the detector.
* The numbers describe this simulator's idea of "normal" (a few requests per window during the day).
  A different user would need to retrain.
* Night access and brute force score low with the model alone because few normal windows resemble them in
  *every* feature; the rules exist precisely for those cases.
