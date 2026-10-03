# Verification notes

The integrity suite covers canonical non-finite rejection, path containment, alteration of events/reports/receipts, checkpoint tampering, deletion relative to a retained checkpoint, Merkle inclusion for odd tree sizes, public-key binding, COCO/YOLO object-count consistency, static rejection of unsafe artifacts, independently pinned references, prevention of self-approved submitted keys, transactional replay/sequence rejection and calibration abstention. It also checks that scenario answer keys do not occur in detection code.

Run the suite using a compatible interpreter:

```sh
python3 -m unittest discover -s tests -v
```

The interface was exercised through all eleven views in a DOM environment, including asynchronous API loading. Interaction checks covered filtering, finding and image inspection, record details, signed inference creation, receiving, replay rejection, evaluation metrics and dependency tracing. Selective reassessment retained 16 unaffected claims and sealed a new linked report. The optional TRAK adapter also completed an integration check with eight fixture inputs and two targets; this verifies execution compatibility and is not a claim about actual training-data influence. Full browser screenshot automation could not start within the restricted execution environment, so a pixel-level screenshot review is not claimed. The workspace is available in the local browser for visual inspection.

Scenario assessments are computed locally from input assets. The supported detector reconstruction was compared numerically with its approved ONNX reference before execution. Envelope verification, original-input bindings, re-execution prerequisites, held-out trigger confirmations and measured reference shifts are individually reported. Finite scenario results are not generalised security performance claims.

Evaluation runs after detection, uses explicit image-stem and finding-family matching, and counts each image once per family. It reports the matching types and missed examples. Different detector families measure different conditions; a detector may identify another legitimate anomaly in a sample that is negative for the evaluated condition. These fixture metrics do not calibrate attack probabilities.

## Motion interface update

The revised interface was checked using the real local styles, scripts and saved assessment data in a DOM harness. All 11 routes rendered without script or CSS parsing errors. Finding details, original annotation overlays and evidence filtering remained functional. Scroll controls, the persistent motion toggle, system reduced-motion changes, asynchronous content reveals and the no-IntersectionObserver fallback were exercised. The harness simulates observation and scrolling; it does not establish pixel-level appearance or measured browser frame rate. A full browser screenshot session could not launch within the current sandbox. The assurance engine was unchanged in this presentation update.
