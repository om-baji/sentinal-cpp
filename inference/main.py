import io
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Dict, List

import torch
import torch.nn.functional as F
import torchvision.transforms as T
from fastapi import FastAPI, File, HTTPException, UploadFile
from PIL import Image
from pydantic import BaseModel

sys.path.append(str(Path(__file__).parent.parent))

from models.cnn import CNN
from models.gnn import SyscallGAT, SyscallRGAT
from models.other import SyscallMLPClassifier

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
MODELS: Dict[str, torch.nn.Module] = {}


def _load_state_dict_model(model: torch.nn.Module, path: Path) -> torch.nn.Module:
    state = torch.load(path, map_location=DEVICE)
    model.load_state_dict(state)
    return model


def _load_checkpoint_model(cls, path: Path) -> torch.nn.Module:
    ckpt = torch.load(path, map_location=DEVICE)
    model = cls(**ckpt.get("config", {}))
    model.load_state_dict(ckpt["state_dict"])
    return model


def _register(name: str, model: torch.nn.Module):
    model.to(DEVICE).eval()
    MODELS[name] = model


@asynccontextmanager
async def lifespan(app: FastAPI):
    base_dir = Path(__file__).parent / "models" / "pytorch"

    loaders = {
        "cnn": lambda: _load_state_dict_model(CNN(), base_dir / "best_cnn.pth"),
        "gat": lambda: _load_checkpoint_model(SyscallGAT, base_dir / "best_gat.pt"),
        "rgat": lambda: _load_checkpoint_model(SyscallRGAT, base_dir / "best_rgat.pt"),
        "mlp": lambda: _load_checkpoint_model(
            SyscallMLPClassifier, base_dir / "best_mlp.pt"
        ),
    }

    for name, loader in loaders.items():
        try:
            _register(name, loader())
            print(f"[startup] loaded: {name}")
        except Exception as e:
            print(f"[startup] failed to load '{name}': {e}")

    yield

    MODELS.clear()
    print("[shutdown] models cleared")


app = FastAPI(title="Model Serving", version="1.2.0", lifespan=lifespan)


def _postprocess(logits: torch.Tensor):
    probs = F.softmax(logits, dim=1)
    preds = torch.argmax(probs, dim=1)
    return logits.cpu().tolist(), probs.cpu().tolist(), preds.cpu().tolist()


def _get_model(name: str) -> torch.nn.Module:
    model = MODELS.get(name)
    if model is None:
        raise HTTPException(status_code=404, detail=f"Model '{name}' not loaded")
    return model


class GATPredictRequest(BaseModel):
    x: List[List[float]]
    edge_index: List[List[int]]
    batch: List[int]


class RGATPredictRequest(BaseModel):
    x: List[List[float]]
    edge_index: List[List[int]]
    edge_type: List[int]
    batch: List[int]


class MLPPredictRequest(BaseModel):
    feats: List[List[float]]


class PredictResponse(BaseModel):
    logits: List[List[float]]
    probs: List[List[float]]
    preds: List[int]


@app.get("/health")
def health():
    return {"status": "ok", "device": str(DEVICE), "loaded_models": list(MODELS.keys())}


@app.get("/models")
def list_models():
    return {
        name: {
            "device": str(next(m.parameters()).device),
            "params": sum(p.numel() for p in m.parameters()),
        }
        for name, m in MODELS.items()
    }


@app.post("/predict/gat", response_model=PredictResponse)
def predict_gat(req: GATPredictRequest):
    model = _get_model("gat")
    x = torch.tensor(req.x, dtype=torch.float32, device=DEVICE)
    edge_index = torch.tensor(req.edge_index, dtype=torch.long, device=DEVICE)
    batch = torch.tensor(req.batch, dtype=torch.long, device=DEVICE)
    with torch.no_grad():
        logits = model(x, edge_index, batch)
    logits, probs, preds = _postprocess(logits)
    return PredictResponse(logits=logits, probs=probs, preds=preds)


@app.post("/predict/rgat", response_model=PredictResponse)
def predict_rgat(req: RGATPredictRequest):
    model = _get_model("rgat")
    x = torch.tensor(req.x, dtype=torch.float32, device=DEVICE)
    edge_index = torch.tensor(req.edge_index, dtype=torch.long, device=DEVICE)
    edge_type = torch.tensor(req.edge_type, dtype=torch.long, device=DEVICE)
    batch = torch.tensor(req.batch, dtype=torch.long, device=DEVICE)
    with torch.no_grad():
        logits = model(x, edge_index, edge_type, batch)
    logits, probs, preds = _postprocess(logits)
    return PredictResponse(logits=logits, probs=probs, preds=preds)


@app.post("/predict/mlp", response_model=PredictResponse)
def predict_mlp(req: MLPPredictRequest):
    model = _get_model("mlp")
    feats = torch.tensor(req.feats, dtype=torch.float32, device=DEVICE)
    with torch.no_grad():
        logits = model(feats)
    logits, probs, preds = _postprocess(logits)
    return PredictResponse(logits=logits, probs=probs, preds=preds)


@app.post("/predict/cnn", response_model=PredictResponse)
def predict_cnn(file: UploadFile = File(...)):
    model = _get_model("cnn")
    img = Image.open(io.BytesIO(file.file.read())).convert("L")
    transform = T.Compose([T.Resize((28, 28)), T.ToTensor()])
    x = transform(img).unsqueeze(0).to(DEVICE)
    with torch.no_grad():
        logits = model(x)
    logits, probs, preds = _postprocess(logits)
    return PredictResponse(logits=logits, probs=probs, preds=preds)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
