# Deliverable coverage

Coverage describes executable support and prerequisites. It is not a claim that every attack can be detected.

| Problem deliverable | Current support |
|---|---|
| Model-agnostic assurance framework | Common evidence/claim schema; format and runtime adapters |
| Training-data integrity | COCO/YOLO schema, annotations, identity and sample checks |
| Trigger/backdoor-related data | Texture concentration and class representation anomalies; advisory signals |
| Label flipping/systematic mislabelling | Duplicate-excluded DINOv2/FAISS neighbour disagreement and conflicting duplicate labels |
| Near duplicates/OOD | Perceptual neighbours, semantic concentration and approved-reference novelty |
| Contributor/source risk | Counts, affected-image rates and class coverage with denominators |
| Model integrity/substitution | Pinned digests, static serialization screening and tensor comparisons |
| Backdoor-like behaviour | Supported adapter perturbations and bounded white-box candidate search; finite coverage |
| Fingerprinting/reference battery | Same-input runtime comparison with a stratified reference battery |
| Cryptographic inference provenance | Supplied SHA-256 envelope profile; fresh SHA-384/Ed25519 Shockwave receipts |
| Alteration/substitution/replay | Binding/signature checks; transactional fresh-receipt receiving; bounded example history checks |
| Distribution shift/anomalies | Reference novelty, reproducible kernel MMD and condition indicators; causal explanation can remain unresolved |
| Calibrated risk/confidence | Implemented independent calibration path; no calibration data supplied, so current results abstain |
| Human-readable evidence | Reasons, measurements, affected assets, evidence families, severity and actions |
| Analyst dashboard | Eleven connected views with shared interface and local state |
| Accept/review/quarantine | Deterministic contract recommendation and separate analyst disposition |
| Tamper-evident audit | Event signatures, hash links, signed Merkle checkpoints, prefix consistency and inclusion proofs |
| Offline/air-gapped deployment | Local assets, included DINOv2, bundled Mac dependencies; no runtime download |
| COCO/YOLO datasets | Both annotation parsers; an independent YOLO-label example is included |
| ONNX/PyTorch/TorchScript | ONNX runtime; data-only PyTorch weight adapter; static TorchScript intake and explicit adapter requirement |
| Reproducible challenge scenarios | Five local input packages; answer keys only in evaluation workflow |
| Assurance-report schema | Versioned JSON evidence, contract, claims, snapshots and report signature |
| Reproducible audit log | Signed lifecycle export and independent verification helpers |
| Source/architecture/setup docs | Source files, launcher, CLI, architecture and dependencies included |
| Coverage/assumptions/limitations | This matrix, per-check status and per-report limitations |

The optional semantic witness has a local implementation path but requires model weights. Training attribution imports checkpoint-bound evidence; it can also execute the conditional supported-classifier TRAK adapter when checkpoints and exact training membership are provisioned. Neither absent capability is recorded as a passed check. Arbitrary model architectures, every backdoor family and every processing operation are not covered by the current adapters.
