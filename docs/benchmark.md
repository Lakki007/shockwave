# Benchmark: 24 seeded Attack Lab packages

Policy `shockwave-1.1` · generated 2026-10-04T05:20:33Z · mean 29.8 s per package (forge + assessment).
Rates are pooled across packages with Wilson 95% intervals. Each package was scored against its sealed answer key only after its report was sealed.

## Data attacks (planted samples caught)

| Attack | Recall (95% CI), caught/planted | Per-package median |
|---|---|---|
| exact duplicates | 100.0% (98.4%–100.0%), 232/232 | 100% |
| flooding | 100.0% (98.7%–100.0%), 301/301 | 100% |
| label flips | 47.0% (41.9%–52.1%), 170/362 | 39% |
| near duplicates | 100.0% (94.7%–100.0%), 69/69 | 100% |
| ood | 100.0% (97.2%–100.0%), 135/135 | 100% |
| split leakage | 100.0% (95.9%–100.0%), 89/89 | 100% |
| trigger | 67.1% (62.8%–71.1%), 326/486 | 58% |

## Signed records (tampered records caught)

| Tampering | Detection (95% CI) |
|---|---|
| altered | 100.0% (67.6%–100.0%), 8/8 |
| deleted | 100.0% (70.1%–100.0%), 9/9 |
| fabricated | 88.9% (56.5%–98.0%), 8/9 |
| reordered | 80.0% (37.6%–96.4%), 4/5 |
| replayed | 100.0% (67.6%–100.0%), 8/8 |
| substituted | 100.0% (75.7%–100.0%), 12/12 |
| untrusted | 100.0% (67.6%–100.0%), 8/8 |

## Submitted model

| Mode | Rate (95% CI) | Meaning |
|---|---|---|
| approved | 0.0% (0.0%–39.0%), 0/6 | false-alarm rate (clean control) |
| backdoor | 50.0% (18.8%–81.2%), 3/6 | detection rate |
| benign retrain | 33.3% (9.7%–70.0%), 2/6 | false-alarm rate (clean control) |
| unsafe | 100.0% (61.0%–100.0%), 6/6 | detection rate |

## Processing pipeline

| Mode | Rate (95% CI) | Meaning |
|---|---|---|
| authorised | 0.0% (0.0%–32.4%), 0/8 | false-alarm rate (clean control) |
| bgr | 100.0% (51.0%–100.0%), 4/4 | detection rate |
| class map | 50.0% (21.5%–78.5%), 4/8 | detection rate |
| threshold | 100.0% (51.0%–100.0%), 4/4 | detection rate |

## Untouched images flagged

5.9% (5.6%–6.2%), 1357/23063

Untouched images are pictures the forge did not modify; flags on them are natural data issues in the real-world baseline or false alarms, counted not hidden.

## Decisions

Quarantine: 21, Review: 3

## Semantic witness (SmolVLM-500M) against the answer key

Positive = planted picture (trigger-stamped for *marking*, synthetic render for *photograph*, flipped label for *label*). Threshold 0.5 on the forced-choice token score.

| Question | Planted / untouched | TPR (95% CI) | FPR (95% CI) | AUROC |
|---|---|---|---|---|
| marking | 32 / 48 | 46.9% (30.9%–63.6%), 15/32 | 2.1% (0.4%–10.9%), 1/48 | 0.92 |
| photograph | 18 / 48 | 100.0% (82.4%–100.0%), 18/18 | 31.2% (19.9%–45.3%), 15/48 | 0.91 |
| label | 32 / 48 | 68.8% (51.4%–82.0%), 22/32 | 81.2% (68.1%–89.8%), 39/48 | 0.39 |

AUROC 0.5 is chance. The witness stays advisory: its findings never change a claim on their own.
