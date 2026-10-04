# Verification notes

The integrity suite covers canonical non-finite rejection, path containment, alteration of events/reports/receipts, checkpoint tampering, deletion relative to a retained checkpoint, Merkle inclusion for odd tree sizes, public-key binding, COCO/YOLO object-count consistency, static rejection of unsafe artifacts, independently pinned references, prevention of self-approved submitted keys, transactional replay/sequence rejection and calibration abstention. It also checks that scenario answer keys do not occur in detection code.

Run the suite using a compatible interpreter:

```sh
cd tests && python3 -m unittest test_extensions test_assurance test_engine test_server_http -v
```

`test_extensions` covers YOLO layout detection, decoding, class-aware NMS and letterbox conventions; a real YOLOX-nano run on dataset pictures; the sandbox self-test (network, writes, package reads, file probing and exec denied), sandboxed-versus-in-process numerical equality, containment of a malformed graph and call timeouts; Secure Enclave co-signatures, tamper detection and pinned-key verification; calibration-set independence from every bundled submission; password hashing and role rules. `test_server_http` runs a real server against a throwaway PostgreSQL database: authentication, roles, dispositions, the two-person sign-off rule, cross-origin rejection, account disabling, logout and detection of rows edited in the database. The macOS CI workflow (`.github/workflows/tests.yml`) runs all four suites; Secure Enclave tests skip on virtual machines.

`docs/benchmark.md` reports detection and false-alarm rates over seeded Attack Lab packages with Wilson 95% intervals, plus a question-level evaluation of the semantic witness.

The interface was exercised through all eleven views in a DOM environment, including asynchronous API loading. Interaction checks covered filtering, finding and image inspection, record details, signed inference creation, receiving, replay rejection, evaluation metrics and dependency tracing. Selective reassessment retained 16 unaffected claims and sealed a new linked report. The optional TRAK adapter also completed an integration check with eight fixture inputs and two targets; this verifies execution compatibility and is not a claim about actual training-data influence. Full browser screenshot automation could not start within the restricted execution environment, so a pixel-level screenshot review is not claimed. The workspace is available in the local browser for visual inspection.

Scenario assessments are computed locally from input assets. The supported detector reconstruction was compared numerically with its approved ONNX reference before execution. Envelope verification, original-input bindings, re-execution prerequisites, held-out trigger confirmations and measured reference shifts are individually reported. Finite scenario results are not generalised security performance claims.

Evaluation runs after detection, uses explicit image-stem and finding-family matching, and counts each image once per family. It reports the matching types and missed examples. Different detector families measure different conditions; a detector may identify another legitimate anomaly in a sample that is negative for the evaluated condition. These fixture metrics do not calibrate attack probabilities.

## Current interface

The current interface (Overview, Workbench with Package/Contract/Attack Lab, Evidence with ten tabs, Method, Team) was exercised in a browser against the running server: all routes rendered without console errors; forging a package from the Attack Lab tab sealed its key and selected it; finding dialogs, the embedding explorer, sign-in, password change, dispositions, two-person sign-off and the custody panels were checked against live data. The 80-second autopilot was recorded end to end with headless Chrome.
