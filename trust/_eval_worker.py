"""
Eval worker — subprocess entry point for isolated evaluation.

This module is launched by trust.evaluator.run_isolated_eval() as a fresh
Python subprocess. It never shares a process with the agent's training code.

Usage (internal — called by evaluator.py, not directly by users):
    python -m trust._eval_worker \\
        --checkpoint PATH \\
        --prepare PATH \\
        --nonce HEX

Output:
    Prints 'val_bpb: X.XXXXXX' to stdout on success.
    Exits non-zero on any failure.

Why a separate subprocess?
--------------------------
If the agent's train.py monkey-patches evaluate_bpb() or any imported
function at runtime, that patch lives only in the training process.
This worker starts a fresh interpreter — the agent's runtime state is
completely absent. Combined with the manifest check on prepare.py, this
means the eval always runs against the verified, unmodified code.

What the nonce does here
------------------------
The nonce is printed to stdout as provenance metadata. It is NOT currently
injected into the dataloader sampling order — that would require modifying
prepare.py (a protected file). The architectural slot is here and ready;
a future version using a patched prepare.py inside a TEE would pass the
nonce to make_dataloader() as a shuffle seed, making the exact token
sequence unpredictable to the agent.
"""

import argparse
import importlib.util
import sys
from pathlib import Path


def load_prepare(prepare_path: Path):
    """Dynamically load prepare.py from an explicit path."""
    spec = importlib.util.spec_from_file_location("prepare", prepare_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Isolated evaluation worker — do not call directly."
    )
    parser.add_argument("--checkpoint", required=True, help="Path to model checkpoint.")
    parser.add_argument("--prepare", required=True, help="Path to prepare.py.")
    parser.add_argument("--nonce", required=True, help="Evaluation nonce (provenance).")
    args = parser.parse_args()

    checkpoint_path = Path(args.checkpoint)
    prepare_path = Path(args.prepare)

    if not checkpoint_path.exists():
        print(f"ERROR: checkpoint not found: {checkpoint_path}", file=sys.stderr)
        sys.exit(1)

    if not prepare_path.exists():
        print(f"ERROR: prepare.py not found: {prepare_path}", file=sys.stderr)
        sys.exit(1)

    print(f"eval_worker: nonce={args.nonce}", flush=True)
    print(f"eval_worker: checkpoint={checkpoint_path}", flush=True)
    print(f"eval_worker: prepare={prepare_path}", flush=True)

    # Load prepare.py from the verified path (manifest already checked it)
    try:
        prepare = load_prepare(prepare_path)
    except Exception as exc:
        print(f"ERROR: failed to import prepare.py: {exc}", file=sys.stderr)
        sys.exit(1)

    # Load torch and the checkpoint
    try:
        import torch
    except ImportError:
        print("ERROR: torch not available in this environment.", file=sys.stderr)
        sys.exit(1)

    try:
        checkpoint = torch.load(checkpoint_path, map_location="cpu", weights_only=False)
    except Exception as exc:
        print(f"ERROR: failed to load checkpoint: {exc}", file=sys.stderr)
        sys.exit(1)

    # Reconstruct model and tokenizer from checkpoint
    # The checkpoint is expected to contain 'model_state_dict' and 'model_args'
    # as saved by train.py. If the format differs, this will fail clearly.
    try:
        model_args = checkpoint.get("model_args", {})
        model_state = checkpoint.get("model_state_dict") or checkpoint.get("model")

        if model_state is None:
            print(
                "ERROR: checkpoint has no 'model_state_dict' or 'model' key. "
                "train.py must save a checkpoint with model weights.",
                file=sys.stderr,
            )
            sys.exit(1)

        # The model class lives in the checkpoint's training module context.
        # We reconstruct it using the train.py that the agent last modified —
        # the agent's architectural changes are preserved, only the eval is isolated.
        train_path = checkpoint_path.parent / "train.py"
        if not train_path.exists():
            print(
                f"ERROR: train.py not found at {train_path}. "
                "The worker expects train.py to be in the same directory as the checkpoint.",
                file=sys.stderr,
            )
            sys.exit(1)

        train_spec = importlib.util.spec_from_file_location("train", train_path)
        train_module = importlib.util.module_from_spec(train_spec)
        train_spec.loader.exec_module(train_module)

        model = train_module.GPT(**model_args)
        model.load_state_dict(model_state)
        device = "cuda" if torch.cuda.is_available() else "cpu"
        model = model.to(device)
        model.eval()

        tokenizer = prepare.Tokenizer.from_directory()
        batch_size = checkpoint.get("batch_size", 8)

    except Exception as exc:
        print(f"ERROR: failed to reconstruct model: {exc}", file=sys.stderr)
        sys.exit(1)

    # Run evaluation — this is the isolated, manifest-verified call
    try:
        val_bpb = prepare.evaluate_bpb(model, tokenizer, batch_size)
    except Exception as exc:
        print(f"ERROR: evaluate_bpb failed: {exc}", file=sys.stderr)
        sys.exit(1)

    # Output format expected by evaluator._parse_val_bpb()
    print(f"val_bpb: {val_bpb:.6f}")


if __name__ == "__main__":
    main()
