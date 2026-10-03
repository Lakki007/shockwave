// Explanations shown behind every "?" icon, each tied to the submitted solution section.
export const HELP = {
  task: ['Intended task', 'What the assessed asset is for. It is recorded in the Assurance Contract so acceptance is only ever "for this use".', '§10 Assurance Contract'],
  context: ['Operating context', 'Where the model will run (sensor, terrain, mission). Analyst-validated regression conditions are reused only when the context matches, and a context change marks dependent claims stale.', '§10, §21, §26'],
  access: ['Model access tier', 'What the assessor may do with the submitted model. White-box: weights and gradients, enabling trigger reconstruction. Grey-box/black-box: only inputs and outputs, so the loop falls back to transfer, STRIP and probes. Unavailable methods are reported, never passed.', '§9.3 Access profile, §14.3'],
  mandatory: ['Mandatory claims', 'Claims that must be Supported for an Accept. Any mandatory claim that is unresolved forces Review; a contradicted one (critical evidence) forces Quarantine.', '§24 Decision policy'],
  challenge_budget: ['Challenge budget', 'Total cost units the Contrarian Loop may spend on adaptive tests. Cheap tests cost 1–2, white-box trigger reconstruction 6, an all-class sweep 10. A small budget forces the loop to prioritise; the stop reason is recorded.', '§20 Contrarian Loop'],
  loop_mode: ['Loop mode', 'Exhaustive keeps investigating to characterise every concern for the report. Decisive stops as soon as a critical contradiction already blocks acceptance — faster, with less forensic detail.', '§20 stopping rules'],
  label_method: ['Label method', 'Neighbour plurality flags an object when most duplicate-excluded DINOv2 neighbours carry another label. Confident Learning uses per-class confident thresholds (Northcutt et al.) over the same neighbour votes, which adapts to class difficulty.', '§11.3'],
  neighbours: ['Independent neighbours (k)', 'How many visually similar objects vote on each label. Exact duplicates and objects from the same image are excluded so repetition cannot manufacture agreement.', '§11.2–11.3'],
  label_threshold: ['Label vote threshold', 'Share of neighbour votes another class must reach before a label is questioned. Higher means fewer, more confident label findings.', '§11.3'],
  duplicate_distance: ['Near-duplicate distance', 'Maximum number of differing bits (out of 64) between perceptual hashes for two images to count as near-duplicates.', '§11.2'],
  ood_quantile: ['Reference envelope', 'An object is novel when it is farther from every approved reference crop than this quantile of reference-to-reference distances. Higher is more permissive.', '§11.7'],
  texture_z: ['Texture concentration (robust z)', 'How unusual an image\'s local high-frequency energy must be, in robust z-units across the corpus, before it is reported as possible trigger texture.', '§11.5'],
  robust_margin: ['Robust sub-population margin', 'SPECTRE-inspired screen: the covariance is fitted robustly on each submitted class. The threshold is the largest score seen when the same procedure runs on the approved reference class, times this margin.', '§11.6'],
  patch_similarity: ['Pattern similarity', 'How alike two mined compact patterns must be (cosine of normalised 12×12 descriptors) to belong to the same recurring-pattern cluster.', '§11.5 repeated textures'],
  patch_min_images: ['Minimum distinct pictures', 'A pattern must recur across at least this many distinct pictures (near-duplicate copies count once) to be considered.', '§11.5'],
  trigger_steps: ['Trigger search steps', 'Optimisation steps per target class in Neural-Cleanse-style reconstruction. More steps give smaller, more reliable masks at higher cost.', '§14.1'],
  numerical_tolerance: ['Numerical tolerance', 'Maximum score or box difference allowed when re-executing a signed record or comparing twin pipelines before calling it a mismatch.', '§15, §16.5'],
};

export const ATTACK_HELP = {
  label_flip: 'Rewrites the class of chosen images from one contributor. Detected by duplicate-excluded DINOv2 neighbour votes; visually similar class pairs are genuinely harder.',
  trigger: 'Stamps a coarse checkerboard at the centre of each object and relabels it (dirty-label BadNets poisoning). Detected by recurring-pattern mining, the robust sub-population screen and label votes.',
  flood: 'One contributor submits many copies of a single picture to dominate the data. Near mode re-encodes each copy with slight brightness changes.',
  leakage: 'Copies validation images into the training split, which inflates measured accuracy.',
  ood: 'Inserts procedurally generated non-photographic renders under a real class label.',
  model: 'Approved: identical bytes. Benign retrain: a fine-tune with no trigger — a false-alarm control. Backdoor: the approved model fine-tuned so the trigger flips source→target (real training, ~30 s, cached). Unsafe: a pickle with an executable callable that must never be loaded.',
  pipeline: 'Changes the processing around an unchanged model: remap a class, swap colour channels or raise the score threshold. Caught by the Twin Pipeline and localised to a stage.',
  records: 'Runs the approved model on real images and signs each output with a freshly provisioned edge key, then tampers with chosen records.',
};

export const RECORD_HELP = {
  altered: 'Output edited after signing', fabricated: 'Wrong output, validly re-signed', replayed: 'Old record submitted again', deleted: 'A record removed from the chain',
  reordered: 'Two records swapped', substituted: 'Input image swapped after signing', untrusted: 'Signed by an unregistered key',
};

export const CLAIM_HELP = {
  data_schema: 'Annotations parse and boxes fall inside images.', data_identity: 'Every file has an exact SHA-256/384 identity.', duplication: 'Duplicates do not dominate the data.',
  split_integrity: 'No image appears in more than one split.', labels: 'Labels agree with visually similar, independent examples.', poisoning: 'No evidence of planted patterns or sub-populations.',
  source_risk: 'No contributor is over-represented in evidence.', model_identity: 'The model is the approved artifact.', safe_intake: 'Model files were inspected without unsafe execution.',
  behaviour: 'The model behaves like the approved model on references.', backdoor: 'No conditional trigger behaviour was found within budget.', pipeline: 'Processing matches the authorised path.',
  provenance: 'Records are intact and signed by trusted keys.', replay: 'No record was replayed.', history: 'Record chains are complete and ordered.', reproduction: 'Re-execution reproduces signed outputs.',
  distribution: 'Data matches the approved operating distribution.', calibration: 'Scores are calibrated on independent data.', audit: 'The assessment is reproducible from the signed log.',
};

export const STAGES = [
  ['Intake', 'Preserve & identify'], ['Baseline', 'Data evidence'], ['Model assurance', 'Identity & intake'],
  ['Provenance', 'Signed records'], ['Contrarian loop', 'Adaptive challenges'], ['Decision', 'Policy & seal'],
];

export const METHOD = [
  ['Receive safely', 'Every file is hashed (SHA-256 and SHA-384) and inspected before anything executes. Pickles are scanned opcode by opcode, archives are bounded, ONNX graphs are checked for custom domains and escaping paths. Rejected models are never loaded.', '§8–9', 'inspect_model · static intake'],
  ['Define the contract', 'The Assurance Contract states the task, context, access tier, mandatory claims and thresholds. It is versioned and becomes part of the signed report.', '§10', 'POLICY · validate_policy'],
  ['Build data evidence', 'Exact and perceptual identity, split leakage, DINOv2 + FAISS duplicate-excluded label votes, Confident-Learning confident joint, recurring compact-pattern mining, SPECTRE-inspired robust sub-populations and approved-reference novelty.', '§11–12', 'core.data_checks · forensics.py'],
  ['Check model and pipeline', 'Digests and tensor comparison against independently approved artifacts, an approved ONNX behaviour battery, the Twin Pipeline differential and re-execution of signed records.', '§13, §15–16', 'models.py'],
  ['Challenge what is unresolved', 'The Contrarian Loop turns evidence into hypotheses and picks the permitted test with the highest weight × value × (1 + gap) / cost. Results spawn follow-ups, adaptive hits are confirmed on reserved images, and a random unflagged sample is audited.', '§20–21', 'loop.py'],
  ['Decide by policy', 'Evidence maps to 19 claims (Supported, Weakened, Contradicted, Unresolved). Critical contradictions quarantine; unresolved mandatory claims or missing calibration force review. AI never decides.', '§19, §23–24', 'core.claim_state · finalize'],
  ['Seal and audit', 'The report is SHA-384 digested and Ed25519 signed; every event joins a hash-linked log with signed Merkle checkpoints and inclusion proofs.', '§16–17', 'provenance.py · verify_audit'],
  ['Reassess what changed', 'Assurance Delta traces a changed dependency to the claims it invalidates and re-runs only those checks, keeping verified unaffected evidence linked to the parent report.', '§26', 'lifecycle.py'],
];

export const FAQ = [
  ['Is this hard-coded or a pre-recorded animation?', 'No. Open the Attack Lab, choose your own attacks and parameters, and forge a new package: pixels are stamped, labels rewritten, a model is fine-tuned on the poisoned data and records are signed and tampered on this machine. The assessor has never seen that package. Every number on screen comes from a sealed report you can download and verify with the CLI.'],
  ['How do we know the detector did not read the answer key?', 'The key is written outside the package the assessor reads, its SHA-384 digest is committed to the signed audit log before assessment, and a unit test asserts that no detection module references the key location. The score is computed only after the report is sealed, and it re-checks the commitment.'],
  ['What does it not catch?', 'Visually similar label swaps (for example military vs civilian helicopters) are hard for neighbour voting. Clean-label, physical and adaptive backdoors may evade the finite tests. Without independent calibration data the system abstains from probabilities and recommends Review. These limits are shown in every report.'],
  ['Is any AI making the decision?', 'No. DINOv2 provides representations and optimisation searches for triggers, but a deterministic, versioned policy maps evidence to Accept, Review or Quarantine. Analyst dispositions are recorded separately and never overwrite the computed result.'],
  ['Does it need the internet?', 'No. The encoder weights, models, fonts and interface are local. The server binds to 127.0.0.1 and the page loads nothing from outside.'],
];
