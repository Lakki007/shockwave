# Local visual and model assets

The interface uses a generated abstract fibre-optic background, kept as `app/static/aurora.png`. The image contains gold and blue light trails, navy clouds, a dark central field and no text. It is a decorative illustration, not evidence or a captured operational result.

Generation brief: “Cinematic abstract fibre-optic widescreen, no text or interface; gold upper-corner trails and blue lower-corner trails converging slightly right of centre; mostly dark navy, clouds along the bottom, sparse sparks and ample negative space for white interface text.”

Sora typography is distributed locally under the SIL Open Font License; see `app/static/Sora-license.txt`. The included representation backbone is `facebook/dinov2-small` (DINOv2-S/14), downloaded from the official Hugging Face model repository. See its model card and licence before redistributing it. No external font, image or model request is needed at runtime.

The semantic witness weights are `HuggingFaceTB/SmolVLM-500M-Instruct` (Apache-2.0) and the YOLOX test detector is the official Megvii `yolox_nano.onnx` release (Apache-2.0). Neither is committed; `python3 shockwave.py fetch-models` downloads them on a preparation machine and verifies every file against `data/models.lock.json`. See `NOTICE.md` for all third-party material.
