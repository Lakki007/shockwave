# Third-party material

| Material | Where | Licence | In this repository |
|---|---|---|---|
| Aircraft and vehicle images with COCO/YOLO annotations (Roboflow export; `*.rf.<hash>.jpg` file names) | `data/fixtures/*/submission`, `data/fixtures/*/reference` | **Source and licence to be confirmed by the project owner** | Yes |
| DINOv2-S/14 (`facebook/dinov2-small`) | `data/encoders/dinov2-small` | Apache-2.0 | Yes |
| SmolVLM-500M-Instruct (`HuggingFaceTB/SmolVLM-500M-Instruct`) | `data/encoders/semantic-witness` | Apache-2.0 | No — `shockwave.py fetch-models` |
| YOLOX-nano ONNX (Megvii-BaseDetection/YOLOX release 0.1.1rc0) | `data/models/yolox` | Apache-2.0 | No — `shockwave.py fetch-models` |
| Sora typeface | `app/static/sora.ttf` | SIL Open Font License 1.1 — **the licence text must ship with the font; `Sora-license.txt` is missing and should be added** | Yes |
| Python dependencies (`requirements.txt`) | installed into `.runtime` | Their respective licences | No |

Pinned digests for the downloaded weights are in `data/models.lock.json`.

Attack Lab, calibration and benchmark packages are derived from the images above by stamping patterns, rewriting labels, copying and re-encoding; they inherit the images' licence.
