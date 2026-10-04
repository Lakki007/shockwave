# Shockwave

An offline computer-vision assurance workspace for contributed datasets, models, processing pipelines and inference records. It connects sample evidence to source-level risk, challenges model behaviour, verifies cryptographic bindings, and produces an auditable accept/review/quarantine recommendation.

## Start the workspace

For a demo, double-click **Start Demo.command**: the single-user workspace, no sign-in. **Start Shockwave.command** starts the multi-analyst workspace when PostgreSQL is configured (sign-in, dispositions, two-person sign-off). From a terminal:

```sh
SHOCKWAVE_MULTI=0 python3 launch.py   # demo workspace
python3 launch.py                     # multi-analyst when configured
```

Add `?demo` to the address (http://127.0.0.1:8765/?demo#/overview) for the 80-second autopilot tour; Esc stops it.

Open **http://127.0.0.1:8765**. To check prerequisites without starting the workspace:

```sh
python3 launch.py --doctor
```

The package includes local application assets, DINOv2 weights and a Python dependency directory for **Apple silicon / Python 3.12**. The launcher can use an available compatible local interpreter. Set `SHOCKWAVE_PYTHON` to choose one, or `SHOCKWAVE_PORT` to change the port. The bundled dependencies require macOS 14 or later. For a different platform, provision Python 3.12 and install `requirements.txt` on a connected preparation machine before taking the environment offline. No dependency installation or model download occurs during assessment.

On a new machine (connected, once):

```sh
python3.12 -m pip install -r requirements.txt
python3.12 shockwave.py fetch-models      # VLM witness + YOLOX, verified against data/models.lock.json
python3.12 shockwave.py calibrate         # optional: rebuild the calibration packages (the set itself is committed)
python3.12 shockwave.py warm              # assess the bundled packages so the overview has data
```

## Presentation walkthrough

The click-by-click judge script is in [docs/demo-walkthrough.md](docs/demo-walkthrough.md). Measured detection rates with confidence intervals are in [docs/benchmark.md](docs/benchmark.md).

Five bundled example packages cover synthetic, baseline, adversarial, curated and YOLO-model submissions. They are distinct input scenarios, not preassigned decisions. Assessment results are computed by the local engine. A curated input can still require review under the active policy.

## Visual experience

The overview unfolds the real DINOv2 embedding of the latest assessment as you scroll: sphere, class map, evidence by severity, challenged claims and the sealed decision. Every number on screen is read from a sealed report. Graphite-and-mint styling, fonts and canvases are local; system reduced-motion settings disable animation. The interface works at phone width.

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
python3 shockwave.py benchmark         # seeded Attack Lab evaluation -> docs/benchmark.md
python3 shockwave.py backup <dir>      # state, registry and analyst database (contains private keys)
python3 shockwave.py restore <dir>     # digest-checked; current state is moved aside
python3 shockwave.py keys --seal       # encrypt the Ed25519 key file under the Secure Enclave
python3 shockwave.py fetch-models      # locked model downloads
```

Run the tests with `cd tests && python3 -m unittest test_extensions test_assurance test_engine test_server_http` (the HTTP tests need a local PostgreSQL).

## Evidence and state

Assessment JSON files are in `data/state/runs`. Signing keys, receiver databases, events, checkpoints, curation manifests and content-addressed embedding caches remain local. Export bundles contain public verification material and evidence; they exclude private signing keys. Pin a trusted public key and retain an independent checkpoint when verifying history outside this machine. The packaged source archive excludes private signing material and mutable local receiver databases; new installations create their own assessor key and should produce new reports under it.

The server binds to loopback unless multi-analyst mode is configured and `SHOCKWAVE_BIND` says otherwise. Hardware key custody covers the co-signature only: the Ed25519 key is still a file on disk, and there is no hardware attestation of execution. The Seatbelt sandbox is macOS-specific. Calibrated probabilities describe the Attack Lab's attack families in the calibrated operating context and do not transfer to unseen attacks.

Read [architecture](docs/architecture.md), [coverage](docs/coverage.md), [research foundations](docs/research.md) and [verification](docs/verification.md) for the exact supported methods.
# ShockWave-Repo
