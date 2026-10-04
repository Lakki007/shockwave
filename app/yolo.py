"""Real detector adapters for the YOLO family (§13 execution adapters).

Supported ONNX output layouts (detected from tensor shapes; a pipeline.json "adapter.layout"
can pin one explicitly):

  yolov8   v8 / v9 / v11 exports      (1, 4+C, N)  cx,cy,w,h in input pixels + per-class scores
  yolov5   v5 / v7 exports            (1, N, 5+C)  cx,cy,w,h + objectness + class scores, N = 3 x grid
  yolox    official YOLOX exports     (1, N, 5+C)  undecoded grid offsets, N = grid (strides 8/16/32)
  e2e      v10 / NMS-free exports     (1, K, 6)    x1,y1,x2,y2,score,class

Preprocessing follows each family's reference implementation: letterbox with grey (114) padding,
centred for Ultralytics-style exports and top-left for YOLOX; RGB/255 for Ultralytics, raw BGR
0-255 for YOLOX. Decoding ends with class-aware NMS and maps boxes back to original pixels.
"""
import numpy as np
from PIL import Image

STRIDES = (8, 16, 32)
LAYOUTS = ('yolov8', 'yolov5', 'yolox', 'e2e')
STYLE = {  # (channel order, scale to 0-1, centred letterbox)
    'yolov8': ('RGB', True, True), 'yolov5': ('RGB', True, True), 'e2e': ('RGB', True, True), 'yolox': ('BGR', False, False)}


def _grid(size):
    return sum((size // s) ** 2 for s in STRIDES)


def detect_layout(output_shapes, size, declared=None):
    """Return the output layout for a single-output detector, or None if it is not a YOLO head."""
    if declared:
        if declared not in LAYOUTS:
            raise ValueError(f'Unsupported detector layout: {declared}')
        return declared
    if len(output_shapes) != 1 or len(output_shapes[0]) != 3:
        return None
    _, a, b = output_shapes[0]
    if not isinstance(a, int) or not isinstance(b, int):
        return None
    if a < b and a >= 5:
        return 'yolov8'
    if b == 6 and a <= 1000 and a not in (_grid(size), 3 * _grid(size)):
        return 'e2e'
    if b >= 6 and a == _grid(size):
        return 'yolox'
    if b >= 6 and a == 3 * _grid(size):
        return 'yolov5'
    return None


def num_classes(layout, output_shape):
    _, a, b = output_shape
    return {'yolov8': a - 4, 'yolov5': b - 5, 'yolox': b - 5, 'e2e': None}[layout]


# --------------------------------------------------------------------------- preprocessing

def letterbox(image, size, layout):
    """PIL image -> (1,3,S,S) float32 tensor in the family's convention, plus the inverse transform."""
    order, unit, centred = STYLE[layout]
    image = image.convert('RGB')
    r = min(size / image.width, size / image.height)
    w, h = max(1, round(image.width * r)), max(1, round(image.height * r))
    canvas = Image.new('RGB', (size, size), (114, 114, 114))
    px, py = ((size - w) // 2, (size - h) // 2) if centred else (0, 0)
    canvas.paste(image.resize((w, h), Image.Resampling.BILINEAR), (px, py))
    x = np.asarray(canvas, dtype=np.float32)
    if order == 'BGR':
        x = x[:, :, ::-1]
    if unit:
        x = x / 255.0
    return np.ascontiguousarray(x.transpose(2, 0, 1)[None]), (r, px, py)


def from_unit_rgb(x, layout):
    """Convert the assessor's canonical (B,3,S,S) unit RGB tensor into the family's input convention."""
    order, unit, _ = STYLE[layout]
    if order == 'BGR':
        x = x[:, ::-1]
    if not unit:
        x = x * 255.0
    return np.ascontiguousarray(x, dtype=np.float32)


# --------------------------------------------------------------------------- decoding

def candidates(layout, out, size):
    """Raw output of one image -> (xyxy boxes in input pixels, class-score matrix or None, class ids or None)."""
    if layout == 'yolov8':
        p = out.T
        cxcywh, cls = p[:, :4], p[:, 4:]
    elif layout == 'yolov5':
        cxcywh, cls = out[:, :4], out[:, 5:] * out[:, 4:5]
    elif layout == 'yolox':
        grids, strides = [], []
        for s in STRIDES:
            n = size // s
            yv, xv = np.meshgrid(np.arange(n), np.arange(n), indexing='ij')
            grids.append(np.stack((xv, yv), 2).reshape(-1, 2))
            strides.append(np.full((n * n, 1), s))
        g, st = np.concatenate(grids), np.concatenate(strides)
        cxcywh = np.concatenate(((out[:, :2] + g) * st, np.exp(np.clip(out[:, 2:4], -10, 10)) * st), 1)
        cls = out[:, 5:] * out[:, 4:5]
    elif layout == 'e2e':
        return out[:, :4].astype(np.float32), out[:, 4].astype(np.float32), out[:, 5].astype(int)
    else:
        raise ValueError(layout)
    xyxy = np.concatenate((cxcywh[:, :2] - cxcywh[:, 2:] / 2, cxcywh[:, :2] + cxcywh[:, 2:] / 2), 1)
    return xyxy.astype(np.float32), cls.astype(np.float32), None


def nms(boxes, scores, iou=0.45):
    order, keep = scores.argsort()[::-1], []
    area = (boxes[:, 2] - boxes[:, 0]).clip(0) * (boxes[:, 3] - boxes[:, 1]).clip(0)
    while order.size:
        i = order[0]
        keep.append(i)
        xx1 = np.maximum(boxes[i, 0], boxes[order[1:], 0]); yy1 = np.maximum(boxes[i, 1], boxes[order[1:], 1])
        xx2 = np.minimum(boxes[i, 2], boxes[order[1:], 2]); yy2 = np.minimum(boxes[i, 3], boxes[order[1:], 3])
        inter = (xx2 - xx1).clip(0) * (yy2 - yy1).clip(0)
        order = order[1:][inter / (area[i] + area[order[1:]] - inter + 1e-9) <= iou]
    return np.array(keep, dtype=int)


def decode(layout, out, size, conf=0.25, iou=0.45, max_det=100):
    """One image's raw output -> list of (class, score, xyxy in input pixels), best first."""
    boxes, cls, ids = candidates(layout, out, size)
    if ids is None:
        ids, scores = cls.argmax(1), cls.max(1)
    else:
        scores = cls
    m = scores >= conf
    boxes, scores, ids = boxes[m], scores[m], ids[m]
    if not len(scores):
        return []
    if layout != 'e2e':  # class-aware NMS: offset boxes by class so classes never suppress each other
        keep = nms(boxes + ids[:, None] * (size * 4.0), scores, iou)
        boxes, scores, ids = boxes[keep], scores[keep], ids[keep]
    order = scores.argsort()[::-1][:max_det]
    return [(int(ids[i]), float(scores[i]), boxes[i].tolist()) for i in order]


def class_scores(layout, out, size):
    """Per-class score vector of the strongest candidate (black-box score access for the loop)."""
    boxes, cls, ids = candidates(layout, out, size)
    if ids is not None:
        v = np.zeros(int(ids.max()) + 1 if len(ids) else 1, dtype=np.float32)
        if len(ids):
            v[ids[cls.argmax()]] = cls.max()
        return v
    return cls[cls.max(1).argmax()]


# --------------------------------------------------------------------------- adapter

class Detector:
    """Wraps a raw-output callable (in-process ONNX Runtime or the sandboxed worker)."""

    def __init__(self, raw, layout, size, names=None):
        self.raw, self.layout, self.size, self.names = raw, layout, size, names or []

    def detect(self, image, conf=0.25, iou=0.45, max_det=100):
        if not isinstance(image, Image.Image):
            with Image.open(image) as im:
                image = im.convert('RGB')
        x, (r, px, py) = letterbox(image, self.size, self.layout)
        out = []
        for c, s, (x1, y1, x2, y2) in decode(self.layout, self.raw(x)[0][0], self.size, conf, iou, max_det):
            x1, x2 = np.clip([(x1 - px) / r, (x2 - px) / r], 0, image.width)
            y1, y2 = np.clip([(y1 - py) / r, (y2 - py) / r], 0, image.height)
            out.append({'class_id': c, 'class_name': self.names[c] if 0 <= c < len(self.names) else str(c), 'score': round(s, 6),
                        'bbox': [round(float(x1), 2), round(float(y1), 2), round(float(x2 - x1), 2), round(float(y2 - y1), 2)]})
        return out

    def prediction(self, x):
        """Top detection for a canonical unit-RGB tensor: (class, score, normalised cx,cy,w,h)."""
        best = decode(self.layout, self.raw(from_unit_rgb(x, self.layout))[0][0], self.size, conf=0.0, max_det=1)
        if not best:
            return 0, 0.0, [0.5, 0.5, 0.0, 0.0]
        c, s, (x1, y1, x2, y2) = best[0]
        return c, s, [(x1 + x2) / 2 / self.size, (y1 + y2) / 2 / self.size, (x2 - x1) / self.size, (y2 - y1) / self.size]

    def probabilities(self, x):
        rows = []
        for i in range(len(x)):
            v = class_scores(self.layout, self.raw(from_unit_rgb(x[i:i + 1], self.layout))[0][0], self.size)
            rows.append(v / (v.sum() + 1e-9))
        width = max(len(r) for r in rows)
        return np.stack([np.pad(r, (0, width - len(r))) for r in rows])
