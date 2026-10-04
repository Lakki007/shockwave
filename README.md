# Shockwave

An offline computer-vision assurance workspace for contributed datasets, models, processing pipelines and inference records. It connects sample evidence to source-level risk, challenges model behaviour, verifies cryptographic bindings, and produces an auditable accept/review/quarantine recommendation.

## Start the workspace

On this Mac, double-click **Start Shockwave.command**, or run:

```sh
python3 launch.py
```

Open **http://127.0.0.1:8765**. To check prerequisites without starting the workspace:

```sh
python3 launch.py --doctor
```

The package includes local application assets, DINOv2 weights and a Python dependency directory for **Apple silicon / Python 3.12**. The launcher can use an available compatible local interpreter. Set `SHOCKWAVE_PYTHON` to choose one, or `SHOCKWAVE_PORT` to change the port. The bundled dependencies require macOS 14 or later. For a different platform, provision Python 3.12 and install `requirements.txt` on a connected preparation machine before taking the environment offline. No dependency installation or model download occurs during assessment.

## Presentation walkthrough

1. Open **Intake & contract**. Select *Adversarial submission* and COCO. Set the intended context, access tier, mandatory claims and challenge budget.
2. Run assurance. Follow intake, baseline evidence, model inspection, provenance, active challenges and the final decision.
3. Open **Data integrity**. Filter findings, inspect original images with annotation boxes, read measurements and compare contributor rates. Exclusion manifests retain evidence and show class coverage after curation.
4. Open **Model assurance**. Inspect blocked artifacts, pinned model identities, weight differences, reference-battery comparisons and conditional tests. Unsupported access is unresolved.
5. Open **Twin pipeline**. Inspect same-model output differences caused by supported processing and label-map changes.
6. Open **Provenance rail**. Inspect signed envelopes and failures. Create a fresh local inference receipt with an approved model; verify/receive it, then submit it again to demonstrate persisted replay rejection.
7. Open **Distribution shift** and **Claims & decisions**. Distinguish measured anomalies from calibrated probabilities, review mandatory claims, and record an analyst disposition with a reason.
8. Open **Assurance delta**. Select a changed dependency, trace stale claims and revalidate affected evidence while retaining verified unaffected evidence.
9. Open **Audit trail**, then **Reports & coverage**. Verify the signed history, export a report/evidence bundle and inspect the separate evaluation workbench.

Five bundled example packages cover synthetic, baseline, adversarial, curated and YOLO-model submissions. They are distinct input scenarios, not preassigned decisions. Assessment results are computed by the local engine. A curated input can still require review under the active policy.

## Visual experience

The overview introduces data, model and inference assurance through an animated core and direct links into the evidence. Every screen uses staggered scroll reveals, local gold/blue light trails, pointer highlights and responsive glass panels. The scroll indicator and back-to-top control support longer evidence screens. Select **Motion on** in the header to pause effects; the choice is retained on this browser. System reduced-motion settings automatically disable motion. All graphics, fonts and effects remain local, and the presentation never changes evidence values or assessment decisions.

## Import a new submission

The ZIP importer accepts a containing directory and normalises it. A complete package uses:

```text
submission/
  coco/{train,valid,test}/_annotations.coco.json + images
  yolo/images/{train,valid,test}/ + labels/{train,valid,test}/ + classes.json
  models/
  records/records.jsonl + inputs/
  pipeline.json
reference/coco/
trust/trust.json + models/
```

A standalone COCO or YOLO dataset can also be imported. ZIP intake is bounded and rejects traversal, encrypted entries and symbolic links. Submitted model objects stay quarantined until screened. **Imported trust material cannot approve itself.** Independently provision approved keys, model digests and reference identities in `data/trust-registry.json`; the bundled registry belongs to the example scenarios. Production keys are provisioned by the operator.

## What executes locally

- COCO and YOLO schema/annotation validation; SHA-256/SHA-384 identity.
- Exact/near duplicates, cross-split leakage, conflicting duplicate labels and flooding evidence.
- DINOv2 object embeddings, FAISS neighbour voting, representation/texture anomaly evidence and source aggregation.
- Static model screening; approved model byte/tensor comparisons; supported ONNX and data-only detector runtime adapters.
- Behaviour fingerprints, bounded perturbations, white-box trigger candidates with held-out confirmations and access-aware fallbacks.
- Same-model Twin Pipeline comparison and compatible signed-output re-execution.
- Edge-envelope verification; fresh Shockwave receipts; transactional nonce, sequence and predecessor checks.
- Reference novelty, permutation MMD, condition indicators and unresolved cause reporting.
- Claim reasoning, policy decisions, analyst dispositions, curation manifests and selective lifecycle revalidation.
- Signed reports, hash-linked Merkle history, checkpoint consistency and inclusion proofs.
- Independent calibration on a held-out Attack Lab set; explicit abstention on context shift or overlap.

## Hardened assessment

- **Calibration set.** `python3 shockwave.py calibrate` forges three Attack Lab packages from approved *reference* pictures that appear in no submission (fit and validation bases share no pictures), assesses them, and labels every picture planted/clean from the sealed answer keys. Assessments then fit isotonic calibration on it and report held-out Brier and ECE, but only when the operating context matches and the distribution-shift test passes; otherwise they abstain. Probabilities are attached to dataset images only.
- **YOLO detector adapters.** `app/yolo.py` runs v5/v7, v8/v9/v11, YOLOX and NMS-free (v10) ONNX exports with each family's letterbox convention, decoding and class-aware NMS. A `pipeline.json` `adapter.layout` field can pin the layout. Tested against the official YOLOX-nano release (`data/models/yolox`, Apache-2.0, not committed).
- **Sandboxed execution.** Submitted graphs never run inside the assessor. `app/sandbox.py` starts a worker under a deny-by-default macOS Seatbelt profile (no network, no file writes, no package reads, no exec) with CPU, file-size and descriptor limits and per-call timeouts; model bytes and tensors cross a pipe. Every assessment self-tests the sandbox first. Without an OS sandbox the submitted model is not executed unless `SHOCKWAVE_ALLOW_UNSANDBOXED=1`.
- **Hardware-backed keys.** On a Mac with a Secure Enclave, reports and audit checkpoints are co-signed by a non-exportable P-256 key generated inside the enclave (`native/se_signer.swift`, built on first use). The Ed25519 signature is kept. Verify with `shockwave.py verify report.json --public-key <ed25519> --hardware-key <p256-der-b64>`; `shockwave.py keys` prints both public keys.
- **Semantic witness.** SmolVLM-500M-Instruct (Apache-2.0) at `data/encoders/semantic-witness`, pinned by SHA-256 in `APPROVED.json` and refused if any file changes. Twelve bounded forced-choice questions per run; advisory only. Weights are not committed (about 1 GB); place them there and keep the pin.
- **Multi-analyst server.** With PostgreSQL configured (`data/state/database.json` or `SHOCKWAVE_DATABASE_URL`), the workspace requires sign-in. Roles are analyst, reviewer and admin; analysts record per-finding dispositions, and a run is signed off only when two different people record the same recommendation, at least one a reviewer, after every critical finding has a disposition. Every row is also written to the signed audit log; `shockwave.py analysts verify` detects rows edited in the database. `shockwave.py analysts init` creates the schema and the first admin, whose temporary password is written to `data/state/initial-admin.txt`. Set `SHOCKWAVE_MULTI=0` to return to the single-user demo workspace. To serve other machines, set `SHOCKWAVE_BIND=0.0.0.0`, put a TLS reverse proxy in front and set `SHOCKWAVE_TLS=1` and `SHOCKWAVE_PUBLIC_HOST`.

Training attribution still requires compatible training checkpoints and a model-bound evidence artifact. TorchScript execution outside approved adapters is not supported. These conditions remain visible in the coverage screen and reports.

## CLI

Use a compatible Python interpreter with the bundled dependencies:

```sh
python3 shockwave.py doctor
python3 shockwave.py run hostile
python3 shockwave.py run yolo --format YOLO
python3 shockwave.py view <run-id>
python3 shockwave.py audit
python3 shockwave.py verify report.json --public-key <trusted-base64-public-key> [--hardware-key <p256-der-b64>]
python3 shockwave.py keys              # Ed25519 and Secure Enclave public keys
python3 shockwave.py sandbox           # self-test the execution sandbox
python3 shockwave.py calibrate         # rebuild the independent calibration set
python3 shockwave.py analysts init     # create the schema and first admin (PostgreSQL)
python3 shockwave.py analysts verify   # cross-check analyst rows against the audit log
```

## Evidence and state

Assessment JSON files are in `data/state/runs`. Signing keys, receiver databases, events, checkpoints, curation manifests and content-addressed embedding caches remain local. Export bundles contain public verification material and evidence; they exclude private signing keys. Pin a trusted public key and retain an independent checkpoint when verifying history outside this machine. The packaged source archive excludes private signing material and mutable local receiver databases; new installations create their own assessor key and should produce new reports under it.

The server binds to loopback unless multi-analyst mode is configured and `SHOCKWAVE_BIND` says otherwise. Hardware key custody covers the co-signature only: the Ed25519 key is still a file on disk, and there is no hardware attestation of execution. The Seatbelt sandbox is macOS-specific. Calibrated probabilities describe the Attack Lab's attack families in the calibrated operating context and do not transfer to unseen attacks.

Read [architecture](docs/architecture.md), [coverage](docs/coverage.md), [research foundations](docs/research.md) and [verification](docs/verification.md) for the exact supported methods.
# ShockWave-Repo
