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
| Calibrated risk/confidence | Isotonic calibration on an independent 788-sample Attack Lab set forged from held-out reference pictures; held-out Brier/ECE reported; abstains on context shift, overlap or an unmeasured context; dataset images only |
| Human-readable evidence | Reasons, measurements, affected assets, evidence families, severity and actions |
| Analyst dashboard | Overview, Workbench, Evidence (10 tabs), Method and Team views; single-user demo or signed-in multi-analyst mode |
| Accept/review/quarantine | Deterministic contract recommendation; per-finding analyst dispositions and two-person sign-off recorded separately |
| Tamper-evident audit | Event signatures, hash links, signed Merkle checkpoints, prefix consistency and inclusion proofs |
| Offline/air-gapped deployment | Local assets, included DINOv2, bundled Mac dependencies; `fetch-models` pulls the VLM and YOLOX once on a preparation machine against a SHA-256 lock; no runtime download |
| COCO/YOLO datasets | Both annotation parsers; an independent YOLO-label example is included |
| ONNX/PyTorch/TorchScript | ONNX runtime with tinydet and YOLO-family adapters (v5/v7, v8/v9/v11, YOLOX, NMS-free); data-only PyTorch weight adapter; static TorchScript intake, no TorchScript execution |
| Untrusted model execution | Submitted graphs run in a macOS Seatbelt worker: no network, file writes, package reads, file probing or exec; rlimits and per-call timeouts; self-tested every run |
| Key custody | Reports and audit checkpoints co-signed by a non-exportable Secure Enclave P-256 key; optional sealing of the Ed25519 key file under the enclave |
| Multi-analyst operation | PostgreSQL accounts and roles, append-only dispositions, two-person sign-off, rows cross-checked against the signed audit log, persistent job queue, backup/restore |
| Evaluation at scale | `shockwave.py benchmark`: seeded Attack Lab packages scored against sealed keys with Wilson 95% intervals; see `benchmark.md` |
| Reproducible challenge scenarios | Five local input packages; answer keys only in evaluation workflow |
| Assurance-report schema | Versioned JSON evidence, contract, claims, snapshots and report signature |
| Reproducible audit log | Signed lifecycle export and independent verification helpers |
| Source/architecture/setup docs | Source files, launcher, CLI, architecture and dependencies included |
| Coverage/assumptions/limitations | This matrix, per-check status and per-report limitations |

The semantic witness (SmolVLM-500M, pinned) is advisory only and its question-level accuracy is measured in `benchmark.md`. Training attribution imports checkpoint-bound evidence; it can also execute the conditional supported-classifier TRAK adapter when checkpoints and exact training membership are provisioned. Absent capabilities are never recorded as passed checks. Arbitrary model architectures, TorchScript execution, every backdoor family and every processing operation are not covered. Isolation is a macOS process sandbox, not a virtual machine.
