# Shockwave architecture

Shockwave is an offline computer-vision assurance workspace. The workflow is **intake → contract → baseline → reasoning → targeted challenges → recommendation → signed assurance record**. Local workers produce evidence; deterministic policy decides the recommendation. Advisory AI cannot admit assets.

| Component | Responsibility |
|---|---|
| `app/server.py` | Loopback API, quarantined ZIP intake, asynchronous assessments, analyst dispositions, curation and exports |
| `app/core.py` | COCO/YOLO inventory, exact identity, duplication, label consistency, source aggregation, shift, claims and signed lifecycle log |
| `app/models.py` | Static model screening, approved reference bindings, tensor differences, ONNX runtime, validated detector adapter, behavioural fingerprint, conditional tests, bounded trigger inversion, Twin Pipeline and re-execution |
| `app/extensions.py` | Optional local semantic witness, bound attribution evidence, independent calibration and abstention |
| `app/lifecycle.py` | Content snapshots, dependency closure, verified parent reports and selective evidence reuse |
| `app/provenance.py` | Domain-separated signed inference receipts, transactional nonce/sequence receiver state, report verification and Merkle inclusion proofs |
| `app/static/` | Shared dark, gold-and-blue interface, evidence explorer, annotated images, model/provenance/shift views, claim decisions, Assurance Delta and coverage |
| `app/yolo.py` | YOLO-family output layouts, letterbox preprocessing, decoding and class-aware NMS |
| `app/sandbox.py`, `app/worker.py` | Seatbelt-sandboxed worker process for submitted graphs; self-test and resource limits |
| `app/keystore.py`, `native/se_signer.swift` | Secure Enclave co-signing and sealing of the Ed25519 key file |
| `app/calibration.py` | Independent calibration set from held-out reference pictures |
| `app/analysts.py` | PostgreSQL multi-analyst accounts, sessions, dispositions and two-person sign-off |
| `app/benchmark.py` | Seeded evaluation at scale with Wilson intervals and the witness study |
| `app/backup.py`, `app/provision.py` | Backup/restore with digests; locked model downloads |
| `shockwave.py` | Offline doctor, run, view, serve, audit, verify, keys, sandbox, calibrate, benchmark, analysts, backup, restore, fetch-models |

## Data assurance

The intake parser accepts COCO bounding boxes and normalised YOLO text labels. Per-image SHA-256 and SHA-384 digests retain exact identity. Byte duplicates, perceptual neighbours, cross-split leakage and conflicting annotations provide distinct evidence. DINOv2-S/14 object embeddings run locally; FAISS indexes normalised vectors. Duplicate images are excluded from label voting. Local texture concentration, within-class representation outliers and dense semantic neighbourhoods identify candidate poisoning, unusual content and flooding. Every alert retains measurements and alternative benign explanations.

Approved reference identities are pinned independently in `data/trust-registry.json`. Reference-space novelty and a reproducible kernel MMD permutation test measure shift. Brightness, blur and texture comparisons support inspection; without acquisition metadata, the cause remains unresolved. Source rates include their image denominator and identify affected contributions rather than accusing contributors.

## Model and pipeline assurance

Unsafe pickle callables, decompression amplification, custom ONNX domains and external tensor path escapes are blocked. The application does not deserialize arbitrary Python model objects. Safe tensor files are parsed as data. Tensor and byte comparisons require independently approved references. A supported detector architecture is reconstructed from data-only weights and checked numerically against approved ONNX before use. Standard ONNX models run with the CPU provider.

Reference batteries and class-pair perturbations are bounded by the declared access and budget. White-box trigger inversion uses a shared candidate pattern, a fixed seed, a recorded search count and held-out confirmation images. Its result is a candidate condition; ordinary adversarial sensitivity remains possible. Unsupported architectures abstain. No finite battery establishes that every backdoor is absent. Analyst-validated measured conditions enter a local, digest-bound regression library; future matching contexts prioritise their allowlisted perturbation families within the same budget.

The Twin Pipeline compares the same approved model and original inputs through supported submitted/control processing paths. Current adapters support fixed-shape resize, RGB/BGR, unit normalisation, class maps and score thresholds. Arbitrary transforms and full NMS variants require further adapters; the report must not describe these as executed. Verified inference envelopes are independently re-executed when their exact configuration is compatible with the approved runtime.

## Reasoning and lifecycle

Findings bind a method version, policy, affected asset, claim, source, evidence family, severity, measurements, reasons and recommended action. Claims can be Supported, Weakened, Contradicted, Unresolved or Stale. Critical integrity contradictions quarantine; unresolved mandatory claims or calibration require review. Analyst dispositions are separately signed events and never rewrite the computed result.

Curation creates a non-destructive exclusion manifest with before/after class counts. Assurance Delta traces dependency changes into stale claims. A new assessment seals fresh evidence and retains history. Targeted revalidation verifies the parent report, recomputes asset snapshots, closes declared and actual dependency changes, and reruns the affected checks. Unaffected evidence retains a parent-report reference. Partial stage execution is conservative: a stage may compute more observations than the invalidated claims, but only evidence for affected claims is appended.

The local Merkle log verifies event signatures, hash links, checkpoint signatures and prefix-root consistency. Inclusion proofs are available. Completeness and rollback detection depend on independently retained checkpoints and a trusted public key. The log is append-only JSON Lines, fsynced per event and guarded by a cross-process lock. On a Mac with a Secure Enclave, every checkpoint and report is also co-signed by a non-exportable P-256 enclave key; the Ed25519 key file can be sealed under the enclave (`shockwave.py keys --seal`). Keys are excluded from exports.

## Provenance profiles

Supplied example envelopes use sorted compact JSON, SHA-256 and Ed25519 over the binary digest. Their freshness check is scoped to the supplied session history. Newly produced Shockwave receipts use versioned sorted UTF-8 JSON, SHA-384, domain-separated canonical bytes, an original-input binding, exact approved-model identity, processing identity, output digest, nonce, monotonic sequence and predecessor. This defined canonicalisation profile is **not claimed to be RFC 8785 JCS**.

Receipt production and receiving use SQLite transactions. The receiver rejects reused nonces, reused session/sequence, gaps and predecessor inconsistencies. This strengthens persisted freshness; a signed claim still does not prove the producer physically executed the model.

## Conditional AI

DINOv2 is included. The semantic witness is SmolVLM-500M-Instruct, fetched once against `data/models.lock.json` and refused at load time if any file differs from its pin. It asks eight bounded forced-choice questions per run (marking and photograph; the label question scored below chance in the benchmark and is not asked), runs without tools or remote code and is advisory only. Training attribution accepts a separately generated, checkpoint-bound evidence artifact; a supported-classifier TRAK adapter is included, while training checkpoints and membership are not supplied, and imported attribution remains Limited. Calibration uses disjoint fit/validation samples, policy and context gates, isotonic regression, Brier score and ECE; absent calibration, a shifted context or an unmeasured context causes abstention. The calibration set is labelled from the sealed keys of its own packages, forged from reference pictures held out of every submission; the answer keys of assessed packages never feed detectors or calibration.

## Execution isolation and its roadmap

Submitted graphs run in a worker under a deny-by-default Seatbelt profile (`app/sandbox.py`): only the Python runtime and system libraries are readable, file metadata outside them is hidden, and network, writes and process execution are denied. Model bytes and tensors cross a pipe, so the worker never sees package paths. Every assessment runs a self-test that tries each escape and records the result in the report.

`sandbox-exec` is deprecated by Apple, although the kernel enforcement it uses remains in macOS. The planned path is a short-lived virtual machine per submission (Apple Virtualization framework on macOS, a microVM such as Firecracker on Linux) speaking the same pipe protocol as `app/worker.py`, so the assessor side does not change. TorchScript execution is deferred until that VM boundary exists, because TorchScript graphs can call arbitrary operators.
