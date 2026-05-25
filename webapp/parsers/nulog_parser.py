"""
NuLog log-parsing backend — self-supervised template extraction.

Implements the NuLog algorithm (Nedelkoski et al., ECML-PKDD 2020) as a
clean, CPU-only module behind the LogParser interface.

How it works
────────────
1. TOKENIZE   all log lines into word sequences, build a vocabulary.
2. TRAIN       a small transformer encoder with masked language modeling:
               randomly mask tokens, train the model to predict them.
               This is self-supervised — the logs ARE the training data.
3. INFER       for each log, mask every token one at a time.
               If the model predicts the original token → CONSTANT (template).
               If it fails → VARIABLE (parameter, replaced with <*>).
4. CLUSTER     group identical templates → cluster IDs.

Why this works: "ERROR" appears predictably in context across thousands of
logs, so the model learns it. "192.168.1.5" could be any IP — the model
can't guess it, so it's a variable.

Architecture: 2-layer transformer encoder, 128-dim, 4 heads (~200K params).
Trains in seconds on 2k logs, minutes on 100k. CPU only — no GPU needed.

Usage
─────
    from webapp.parsers.nulog_parser import NuLogParser
    parser = NuLogParser()
    result = parser.parse(open("raw_logs.txt"))

Or via the webapp — select "nulog" from the backend dropdown.

Dependencies: torch (CPU), nothing else.
"""
from __future__ import annotations

import hashlib
import math
import re
import sys
from collections import Counter, defaultdict
from typing import Iterable

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import DataLoader, Dataset

from .base import ClusterInfo, LogParser, ParsedRecord, ParseResult

# ── Hyperparameters ───────────────────────────────────────────────────────────

D_MODEL     = 128       # embedding / hidden dimension
N_HEADS     = 4         # attention heads
N_LAYERS    = 2         # transformer encoder layers
D_FF        = 256       # feed-forward inner dimension
DROPOUT     = 0.1
PAD_LEN     = 64        # max tokens per log line (longer lines truncated)
MASK_RATIO  = 0.15      # fraction of tokens masked during training
BATCH_SIZE  = 64
EPOCHS      = 3         # 3 is enough for log parsing — we're not doing NLU
LR          = 1e-3
TOP_K       = 5         # if true label is in the model's top-K predictions → constant
MIN_VOCAB   = 3         # tokens appearing fewer times → treated as <UNK>
SAMPLE_RECORDS = 500    # max records shipped to the browser (same as drain3 backend)

# ── Special tokens ────────────────────────────────────────────────────────────

PAD_TOKEN  = "<PAD>"
UNK_TOKEN  = "<UNK>"
MASK_TOKEN = "<MASK>"
CLS_TOKEN  = "<CLS>"
SPECIAL    = [PAD_TOKEN, UNK_TOKEN, MASK_TOKEN, CLS_TOKEN]


# ── Vocabulary ────────────────────────────────────────────────────────────────

class Vocab:
    """Word ↔ index mapping with special tokens."""

    def __init__(self, lines: list[list[str]], min_count: int = MIN_VOCAB):
        freq = Counter(tok for line in lines for tok in line)
        self.w2i: dict[str, int] = {}
        self.i2w: dict[int, str] = {}
        for tok in SPECIAL:
            idx = len(self.w2i)
            self.w2i[tok] = idx
            self.i2w[idx] = tok
        for tok, cnt in freq.most_common():
            if cnt < min_count:
                continue
            if tok not in self.w2i:
                idx = len(self.w2i)
                self.w2i[tok] = idx
                self.i2w[idx] = tok

    def encode(self, tok: str) -> int:
        return self.w2i.get(tok, self.w2i[UNK_TOKEN])

    def decode(self, idx: int) -> str:
        return self.i2w.get(idx, UNK_TOKEN)

    def __len__(self) -> int:
        return len(self.w2i)

    @property
    def pad_id(self) -> int:
        return self.w2i[PAD_TOKEN]

    @property
    def mask_id(self) -> int:
        return self.w2i[MASK_TOKEN]

    @property
    def cls_id(self) -> int:
        return self.w2i[CLS_TOKEN]


# ── Tokenizer ─────────────────────────────────────────────────────────────────

# basic pre-masking: collapse obvious numbers/IPs so the model focuses on
# structure, not memorising digits. Lighter than drain3's regex battery.
_PRE_MASKS = [
    (re.compile(r"\b\d{4}-\d{2}-\d{2}[T_ ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b"), "<TS>"),
    (re.compile(r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) +\d{1,2} \d{2}:\d{2}:\d{2}"), "<TS>"),
    (re.compile(r"\b\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?\b"), "<TS>"),
    (re.compile(r"\b\d{6} \d{6}\b"), "<TS>"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b"), "<IP>"),
    (re.compile(r"\b0[xX][0-9a-fA-F]+\b"), "<HEX>"),
    (re.compile(r"\b\d{1,2}:\d{2}:\d{2}(?:[.,]\d+)?\b"), "<TIME>"),
    (re.compile(r"(?<![A-Za-z_./])\d+(?![A-Za-z_./])"), "<NUM>"),
]


def tokenize(line: str) -> list[str]:
    """Whitespace-split with light pre-masking of numbers/IPs."""
    for pat, repl in _PRE_MASKS:
        line = pat.sub(repl, line)
    return line.split()


# ── Dataset ───────────────────────────────────────────────────────────────────

class MaskedLogDataset(Dataset):
    """
    For training: each sample is one log line with random tokens masked.
    For inference: mask_all=True masks every token position (one sample per
    token per line), used to probe which tokens the model can predict.
    """

    def __init__(self, tokenized: list[list[str]], vocab: Vocab,
                 pad_len: int = PAD_LEN, mask_ratio: float = MASK_RATIO,
                 mask_all: bool = False):
        self.vocab = vocab
        self.pad_len = pad_len
        self.mask_ratio = mask_ratio
        self.mask_all = mask_all

        # encode and pad
        self.data: list[list[int]] = []
        self.lengths: list[int] = []
        for toks in tokenized:
            ids = [vocab.cls_id] + [vocab.encode(t) for t in toks[:pad_len - 1]]
            self.lengths.append(len(ids))
            ids += [vocab.pad_id] * (pad_len - len(ids))
            self.data.append(ids)

    def __len__(self) -> int:
        if self.mask_all:
            # one sample per non-special token position per line
            return sum(l - 1 for l in self.lengths)  # -1 for CLS
        return len(self.data)

    def __getitem__(self, idx):
        if self.mask_all:
            # map flat index → (line_idx, token_position)
            line_idx, pos = self._flat_to_pos(idx)
            ids = list(self.data[line_idx])
            label = ids[pos]
            ids[pos] = self.vocab.mask_id
            return (torch.tensor(ids, dtype=torch.long),
                    torch.tensor(label, dtype=torch.long),
                    torch.tensor(line_idx, dtype=torch.long),
                    torch.tensor(pos, dtype=torch.long))
        else:
            ids = list(self.data[idx])
            length = self.lengths[idx]
            # randomly mask tokens (skip CLS at position 0)
            n_mask = max(1, int(self.mask_ratio * (length - 1)))
            positions = torch.randperm(length - 1)[:n_mask] + 1  # +1 to skip CLS
            labels = torch.full((self.pad_len,), -100, dtype=torch.long)
            for p in positions:
                labels[p] = ids[p]
                ids[p] = self.vocab.mask_id
            return (torch.tensor(ids, dtype=torch.long), labels)

    def _flat_to_pos(self, flat_idx: int):
        """Map a flat index to (line_index, token_position)."""
        cumulative = 0
        for i, l in enumerate(self.lengths):
            n_tokens = l - 1  # skip CLS
            if flat_idx < cumulative + n_tokens:
                pos = flat_idx - cumulative + 1  # +1 to skip CLS
                return i, pos
            cumulative += n_tokens
        raise IndexError(f"flat_idx {flat_idx} out of range")


# ── Model ─────────────────────────────────────────────────────────────────────

class NuLogModel(nn.Module):
    """
    Small transformer encoder for masked language modeling on logs.
    ~200K parameters with default hyperparameters. CPU-friendly.
    """

    def __init__(self, vocab_size: int, d_model: int = D_MODEL,
                 n_heads: int = N_HEADS, n_layers: int = N_LAYERS,
                 d_ff: int = D_FF, dropout: float = DROPOUT,
                 pad_len: int = PAD_LEN):
        super().__init__()
        self.embedding = nn.Embedding(vocab_size, d_model, padding_idx=0)
        self.pos_embedding = nn.Embedding(pad_len, d_model)
        self.dropout = nn.Dropout(dropout)

        encoder_layer = nn.TransformerEncoderLayer(
            d_model=d_model, nhead=n_heads, dim_feedforward=d_ff,
            dropout=dropout, batch_first=True, norm_first=True,
        )
        self.encoder = nn.TransformerEncoder(encoder_layer, num_layers=n_layers)
        self.head = nn.Linear(d_model, vocab_size)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """x: (batch, seq_len) → logits: (batch, seq_len, vocab_size)"""
        seq_len = x.size(1)
        positions = torch.arange(seq_len, device=x.device).unsqueeze(0)
        pad_mask = (x == 0)  # True where padding

        h = self.embedding(x) + self.pos_embedding(positions)
        h = self.dropout(h)
        h = self.encoder(h, src_key_padding_mask=pad_mask)
        return self.head(h)


# ── Training ──────────────────────────────────────────────────────────────────

def train_model(tokenized: list[list[str]], vocab: Vocab,
                epochs: int = EPOCHS, batch_size: int = BATCH_SIZE,
                lr: float = LR, verbose: bool = True) -> NuLogModel:
    """Train the MLM on the given tokenized log lines. Returns the model."""
    dataset = MaskedLogDataset(tokenized, vocab)
    loader  = DataLoader(dataset, batch_size=batch_size, shuffle=True,
                         drop_last=False)

    model = NuLogModel(len(vocab))
    optimizer = torch.optim.Adam(model.parameters(), lr=lr)
    criterion = nn.CrossEntropyLoss(ignore_index=-100)

    model.train()
    for epoch in range(epochs):
        total_loss = 0.0
        n_batches  = 0
        for batch_ids, batch_labels in loader:
            logits = model(batch_ids)
            loss = criterion(logits.view(-1, len(vocab)), batch_labels.view(-1))
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()
            total_loss += loss.item()
            n_batches  += 1
        if verbose:
            avg = total_loss / max(n_batches, 1)
            print(f"  nulog epoch {epoch+1}/{epochs}  loss={avg:.4f}",
                  file=sys.stderr)
    return model


# ── Inference ─────────────────────────────────────────────────────────────────

def infer_templates(tokenized: list[list[str]], vocab: Vocab,
                    model: NuLogModel, top_k: int = TOP_K,
                    batch_size: int = BATCH_SIZE) -> list[list[str]]:
    """
    For each log line, mask each token one at a time and check if the model's
    top-K predictions contain the original token.
      - YES → constant (keep the word)
      - NO  → variable (replace with <*>)
    Returns a list of template token lists.
    """
    dataset = MaskedLogDataset(tokenized, vocab, mask_all=True)
    loader  = DataLoader(dataset, batch_size=batch_size, shuffle=False)

    # collect per-position verdicts: (line_idx, pos) → is_constant
    verdicts: dict[tuple[int, int], bool] = {}

    model.eval()
    with torch.no_grad():
        for batch_ids, batch_labels, batch_lines, batch_pos in loader:
            logits = model(batch_ids)
            # gather logits at the masked position for each sample
            for i in range(batch_ids.size(0)):
                pos = batch_pos[i].item()
                line_idx = batch_lines[i].item()
                label = batch_labels[i].item()
                tok_logits = logits[i, pos]
                topk_ids = tok_logits.topk(top_k).indices.tolist()
                verdicts[(line_idx, pos)] = (label in topk_ids)

    # build templates
    templates: list[list[str]] = []
    for line_idx, toks in enumerate(tokenized):
        tmpl = []
        for tok_pos, tok in enumerate(toks):
            pos = tok_pos + 1  # +1 because CLS is at position 0
            if verdicts.get((line_idx, pos), False):
                tmpl.append(tok)
            else:
                tmpl.append("<*>")
        templates.append(tmpl)

    return templates


# ── Post-processing ───────────────────────────────────────────────────────────

def merge_adjacent_wildcards(template: list[str]) -> list[str]:
    """Collapse consecutive <*> tokens into a single <*>."""
    out = []
    for tok in template:
        if tok == "<*>" and out and out[-1] == "<*>":
            continue
        out.append(tok)
    return out


def extract_params(template: list[str], original_tokens: list[str]) -> list[str]:
    """Extract the original values at <*> positions."""
    if len(template) != len(original_tokens):
        return []
    return [orig for tmpl, orig in zip(template, original_tokens)
            if tmpl == "<*>"]


# ── LogParser implementation ──────────────────────────────────────────────────

class NuLogParser(LogParser):
    """NuLog: self-supervised log parsing via masked language modeling."""

    name = "nulog"

    def __init__(self, epochs: int = EPOCHS, top_k: int = TOP_K,
                 batch_size: int = BATCH_SIZE, verbose: bool = True):
        self.epochs     = epochs
        self.top_k      = top_k
        self.batch_size = batch_size
        self.verbose    = verbose

    def parse(self, lines: Iterable[str],
              sample_limit: int = SAMPLE_RECORDS) -> ParseResult:
        # 1. collect and tokenize all lines
        raw_lines:  list[str]       = []
        tokenized:  list[list[str]] = []
        orig_toks:  list[list[str]] = []  # pre-mask originals for param extraction

        for raw in lines:
            log = raw.rstrip("\n")
            if not log.strip():
                continue
            raw_lines.append(log)
            tokenized.append(tokenize(log))
            orig_toks.append(log.split())

        if not raw_lines:
            return ParseResult(self.name, [], [])

        if self.verbose:
            print(f"  nulog: {len(raw_lines)} lines, building vocab...",
                  file=sys.stderr)

        # 2. build vocabulary
        vocab = Vocab(tokenized)
        if self.verbose:
            print(f"  nulog: vocab size = {len(vocab)}", file=sys.stderr)

        # 3. train
        model = train_model(tokenized, vocab, epochs=self.epochs,
                            batch_size=self.batch_size, verbose=self.verbose)

        # 4. infer templates
        if self.verbose:
            print("  nulog: inferring templates...", file=sys.stderr)
        templates = infer_templates(tokenized, vocab, model,
                                    top_k=self.top_k,
                                    batch_size=self.batch_size)

        # 5. post-process and cluster
        cluster_map: dict[str, int] = {}
        cluster_sizes: Counter = Counter()
        next_id = 1

        records:      list[ParsedRecord] = []
        total_lines   = 0
        total_params  = 0
        new_clusters  = 0

        for i, (raw, tmpl_toks, orig) in enumerate(
                zip(raw_lines, templates, orig_toks)):
            # merge adjacent wildcards for cleaner templates
            clean = merge_adjacent_wildcards(tmpl_toks)
            template_str = " ".join(clean)
            params = extract_params(tmpl_toks, tokenize(raw))

            # assign cluster ID
            tmpl_key = template_str
            if tmpl_key not in cluster_map:
                cluster_map[tmpl_key] = next_id
                next_id += 1
                change = "new"
                new_clusters += 1
            else:
                change = "none"

            cid = cluster_map[tmpl_key]
            cluster_sizes[cid] += 1

            total_lines  += 1
            total_params += len(params)

            if len(records) < sample_limit:
                records.append(ParsedRecord(
                    original_log = raw,
                    cluster_id   = cid,
                    template     = template_str,
                    parameters   = params,
                    change_type  = change,
                ))

        # build cluster list
        clusters = []
        tmpl_by_id = {cid: tmpl for tmpl, cid in cluster_map.items()}
        for cid in sorted(tmpl_by_id):
            clusters.append(ClusterInfo(cid, cluster_sizes[cid], tmpl_by_id[cid]))
        clusters.sort(key=lambda c: c.size, reverse=True)

        result = ParseResult(self.name, records, clusters)
        result._total_lines  = total_lines
        result._total_params = total_params
        result._new_clusters = new_clusters

        if self.verbose:
            print(f"  nulog: done — {total_lines} lines, "
                  f"{len(clusters)} clusters", file=sys.stderr)

        return result
