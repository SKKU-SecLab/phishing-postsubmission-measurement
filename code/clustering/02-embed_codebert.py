import json
import numpy as np
import torch
from pathlib import Path
from tqdm import tqdm
from transformers import AutoTokenizer, AutoModel


BASE_DIR   = Path(__file__).resolve().parent.parent.parent
INPUT_PATH = BASE_DIR / "results" / "clustering" / "all_functions.json"
EMB_PATH   = BASE_DIR / "results" / "clustering" / "embeddings_codebert.npy"
IDS_PATH   = BASE_DIR / "results" / "clustering" / "embeddings_ids.json"

EMB_PATH.parent.mkdir(parents=True, exist_ok=True)

MODEL_NAME = "microsoft/codebert-base"
BATCH_SIZE = 128
MAX_LENGTH = 512

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
print(f"Device: {device}")

tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
model     = AutoModel.from_pretrained(MODEL_NAME).to(device)
model.eval()

with open(INPUT_PATH, encoding="utf-8") as f:
    all_data = json.load(f)["items"]
print(f"Loaded {len(all_data)} functions total")

def make_text(item):
    prefix = f"// event:{item.get('event_type','')} phase:{item.get('fn_phase','')}\n"
    src    = item.get("function_source") or ""
    jq     = item.get("jquery_handlers_concat") or ""
    return (prefix + src + "\n" + jq)[:600]

texts  = [make_text(item) for item in all_data]
gt_ids = [item["gt_id"] for item in all_data]

@torch.inference_mode()
def embed_batch(batch_texts):
    enc = tokenizer(
        batch_texts,
        return_tensors="pt",
        padding=True,
        truncation=True,
        max_length=MAX_LENGTH,
    )
    enc = {k: v.to(device) for k, v in enc.items()}
    out = model(**enc)
    return out.last_hidden_state[:, 0, :].cpu().numpy()  # [CLS] token

all_embs = []
for i in tqdm(range(0, len(texts), BATCH_SIZE), desc="Embedding"):
    all_embs.append(embed_batch(texts[i:i+BATCH_SIZE]))

embeddings = np.vstack(all_embs)
print(f"Embedding shape: {embeddings.shape}")

np.save(EMB_PATH, embeddings)
with open(IDS_PATH, "w") as f:
    json.dump(gt_ids, f)

print(f"Saved: {EMB_PATH}")
print(f"Saved: {IDS_PATH}")
