# Judge demo: what to click and what to say

About 6 minutes. **Bold** = click. Quotes = say.

## Before judges arrive
- Double-click **Start Demo.command** (single-user workspace, no sign-in). Open http://127.0.0.1:8765/#/overview.
- Full screen, other tabs closed. Backup: the 80-second autopilot at `http://127.0.0.1:8765/?demo#/overview`, or `docs/shockwave-demo.mp4`.
- Optional: forge one package in advance (step 3) so it is ready if time is short.

## 1. The problem (45 s) — Overview
Show the hero.
> "Vision models are trained on data from many contributors. Any of them can poison labels, plant a trigger, swap the model or tamper with output records. High accuracy doesn't prove integrity, and a valid signature doesn't prove a prediction is right. Shockwave turns that chain into evidence and a decision you can verify."

**Scroll slowly** through the sphere story.
> "Each dot is a real object from the dataset, embedded on this laptop by DINOv2. Labels are checked against independent visual neighbours, never against their own duplicates. Gold and coral points carry evidence."

## 2. Plant the attack yourself (60 s) — Workbench → Attack Lab
**Workbench**, then the **03 Attack Lab** tab. Invite a judge to choose: toggle attacks, change a source/target class, pick a model mode (**Backdoor** is the most impressive), and **Forge package**.
> "This builds a brand-new package from a thousand real images: pixels are stamped, labels rewritten, a model is genuinely fine-tuned on the poison, and records are signed then tampered. The answer key is sealed outside the package and its digest is committed to the signed audit log *before* the assessor runs."

When the toast says the package is forged, it is already selected in **Package**.

## 3. Run it live (60 s)
**02 Contract**: hover a **?** next to *Model access tier*.
> "The Assurance Contract says what the model is for, what access we have, which claims are mandatory and the testing budget. It is sealed into the report."

**Run assurance**. Point at the radar and claim tiles, then the **Contrarian loop** column.
> "Findings stream in by domain and severity; nineteen claims change state as evidence arrives. The Contrarian Loop then chooses the next most useful test within the budget and shows what it beat."
> "The submitted model never runs inside the assessor. It runs in a sandboxed worker with no network, no file access and no ability to start programs; every run self-tests that sandbox first."

When the banner appears:
> "A deterministic policy decides — not AI. Critical contradictions quarantine; unresolved mandatory claims force review."

## 4. Proof it isn't hard-coded (30 s)
**Score against sealed key**.
> "Only now, after the report is sealed, do we open the answer key. It matches the commitment made before the run. Here is what was planted against what was caught — and untouched images that were flagged are counted too."

> "We didn't stop at one package: we ran BENCHMARK_PACKAGES seeded packages and report every rate with a 95% confidence interval." (Numbers: `docs/benchmark.md`.)

## 5. Evidence (60 s) — **Open evidence**
- **Decision**: "Every claim, its state and why. The report is SHA-384 digested and signed."
- **Findings** → **click a row with an image**: "Every finding traces to the image, its box and the raw measurement."
- **Data map** → drag, then **Evidence**: "The embedding is explorable; hover any point to see the real image."
- **Reports & audit**: point at the four custody panels.
  > "The report and every audit checkpoint are co-signed by a key that lives inside this Mac's Secure Enclave and can't be exported. Scores are calibrated on an independent set built from pictures that appear in no submission, and the calibration abstains when the data has shifted. The vision-language witness is pinned by hash and advisory only."

## 6. Close (20 s) — **The Method**
> "Receive safely, define the contract, build data evidence, check model and pipeline, challenge what's unresolved, decide by policy, seal, and reassess only what changed. Fully offline, and every report states its own limits."

## Optional: multi-analyst (60 s, if asked about teams)
Quit the demo window, double-click **Start Shockwave.command**, sign in.
> "With PostgreSQL configured, analysts sign in with roles. Each finding gets a recorded disposition; a run is signed off only when two different people agree, one of them a reviewer, after every critical finding has been reviewed. Every database row is also in the signed audit log, so editing the database behind our back is detected."

## Likely questions
- **Pre-recorded?** No — the judge just chose the attacks; the key was committed before the run.
- **What does it miss?** Look at `docs/benchmark.md`: the weakest families and the false-alarm rate on untouched images are reported, not hidden. Visually similar class swaps and clean-label or adaptive backdoors are hard. Calibration covers only the Attack Lab's attack families.
- **Is AI deciding?** No. DINOv2 gives representations, optimisation searches for triggers, the VLM is advisory; a versioned rule-based policy decides.
- **Internet?** None at runtime. Models are fetched once on a preparation machine against SHA-256 pins.
- **Hardware security?** Reports and checkpoints are co-signed in the Secure Enclave; the Ed25519 key can be sealed under it. There is no hardware attestation of execution, and isolation is a macOS sandbox, not a VM.

## If something breaks
Play the autopilot (`?demo`) or the video and narrate with the same lines.
