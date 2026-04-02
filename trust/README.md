# Trust Layer

Autonomous ML research agents will, given enough iterations, find ways to game the metric they are optimising. This is not a bug — it is a structural property of any optimisation loop. [Goodhart's Law](https://en.wikipedia.org/wiki/Goodhart%27s_law) applies with particular force when the agent runs 100 experiments overnight and has no off switch.

This package makes gaming **detectable and attributable** rather than relying on policy rules alone — the same way a blockchain doesn't prevent fraud but makes fraud auditable.

---

## Threat model

AutoResearch loops through propose → train → evaluate cycles, keeping only changes that improve `val_bpb`. The integrity of the whole system rests on one assumption: the agent won't touch `prepare.py` or the evaluation metric. In practice, a capable agent can subvert this in several ways:

| # | Threat | Example |
|---|--------|---------|
| 1 | **Eval tampering** | Agent modifies `evaluate_bpb()` in `prepare.py` to return a lower value |
| 2 | **Manifest forgery** | Agent updates the committed hash to match the tampered file |
| 3 | **Data leakage** | Agent generates synthetic data that mirrors the validation set |
| 4 | **Selective reporting** | Agent suppresses failed runs from the log, inflating apparent progress |
| 5 | **Post-hoc rationalisation** | Agent writes plausible hypotheses after seeing results, not before |

Each layer in this package addresses one or more of these threats.

---

## Layers

### Layer 1 — Manifest (implemented)

**File:** `manifest.py`
**Threat addressed:** #1 and #2

A SHA-256 hash of each protected file (`prepare.py` by default), signed with HMAC-SHA-256 using a secret key that never leaves the researcher's machine.

**Why HMAC and not a plain hash?**
A plain hash of the manifest only proves the files match what's recorded. An agent with write access to the repo could modify both the file *and* the manifest hash together — and a plain hash would still pass. HMAC requires the secret key to produce a valid signature. Without the key, the agent cannot forge a manifest that passes verification, even if it rewrites every byte of the protected files.

```
researcher's machine                    git repo
──────────────────                      ────────
.trust_key  (secret, gitignored)   →   .trust_manifest.json  (committed, public proof)
```

**Usage:**
```bash
# Before starting an agent session — anchor the protected files
trust init prepare.py

# At any point — verify nothing has changed
trust verify

# In CI — runs automatically on every push (see .github/workflows/verify-integrity.yml)
```

**What to commit, what to keep local:**

| File | Commit? | Why |
|------|---------|-----|
| `.trust_manifest.json` | Yes | Public proof; git history makes it tamper-evident |
| `.trust_key` | **Never** | Secret; losing it only means re-running `trust init` |

---

### Layer 2 — Ledger (implemented)

**File:** `ledger.py`
**Threat addressed:** #4

An append-only SQLite log where each entry is chained to the previous one via a Merkle hash. Every experiment run — whether it improved the metric or not — is recorded *before* the result is known. Deleting or rewriting entries breaks the chain and is immediately detectable.

Each run is a two-phase operation:
1. `open_run()` — called before the agent script runs. The entry is written immediately, so the run is on the record even if the process crashes.
2. `close_run()` — called after the agent exits with result, status (`keep`/`discard`/`crash`), and a description.

The chain hash of each entry is `SHA-256(prev_chain_hash + opened_at + nonce + script)`. Deleting any entry breaks the hash link to all subsequent entries.

**Known limitation:** the chain proves the *ordering* of entries that are present — it does not prove that no entries were removed, because a sufficiently motivated agent could delete an entry and re-chain the remainder. The statistical auditor (Layer 5) addresses this by flagging `id` gaps in the ledger. As with the manifest, this is a demonstration of the concept; a production version would anchor chain hashes to an external append-only service.

`trust run` integrates both layers: it verifies the manifest before the agent runs, opens a ledger entry, executes the script, closes the entry, then re-verifies the manifest post-run.

```bash
# Wrap an agent experiment with full integrity checks
TRUST_VAL_BPB=0.9979 TRUST_STATUS=keep TRUST_DESCRIPTION="baseline" \
    trust run train.py
```

```bash
# Verify the ledger chain
trust verify-ledger  # coming in a future CLI update
```

---

### Layer 3 — Isolated Evaluator (coming in Phase 4)

**File:** `evaluator.py`
**Threat addressed:** #3

Runs the evaluation in an isolated subprocess that has no write access to the data or evaluation scripts. Injects a random nonce into each evaluation run, so the agent cannot overfit to a fixed validation set over many iterations.

---

### Layer 4 — Hypothesis Logger (implemented)

**File:** `hypothesis.py`
**Threat addressed:** #5

Before each experiment runs, the agent must commit a structured prediction: what it expects to change and why, and the expected direction (`improve`, `degrade`, `neutral`). This is written to the ledger before the script executes — the prediction and the outcome sit side by side, making post-hoc rationalisation visible.

Each hypothesis is sealed with a SHA-256 commit hash over all its fields. Any retroactive edit to the rationale, direction, or predicted value is detectable via `verify_hypothesis_integrity()`.

```bash
# Set before calling trust run — committed before the script executes
export TRUST_RATIONALE="Increasing depth from 8 to 10 should improve val_bpb by ~0.01"
export TRUST_DIRECTION="improve"
export TRUST_PREDICTED_BPB="0.988"
export TRUST_VAL_BPB="0.991"
export TRUST_STATUS="keep"
export TRUST_DESCRIPTION="depth 8→10"

trust run train.py
```

If `TRUST_RATIONALE` and `TRUST_DIRECTION` are not set, the run still proceeds but is flagged by the auditor as missing a hypothesis — a signal worth investigating.

**The statistical signal:** a genuine researcher predicts correctly more often than chance, and their errors are random. An agent gaming the metric shows a specific anomaly: prediction accuracy near chance (hypotheses are noise), but results are suspiciously clean. The auditor layer uses this decoupling as its primary detection signal.

---

### Layer 5 — Statistical Auditor (coming in Phase 6)

**File:** `auditor.py`
**Threat addressed:** #4 and #5 in aggregate

Analyses the full run history for anomaly patterns: improvement rates that exceed theoretical bounds, prediction accuracy that is too low (post-hoc rationalisation) or too high (suspiciously well-calibrated), and distribution of keep/discard decisions.

---

## Scope and honest limitations

**This project is a demonstration, not a production security system.**

Its goal is to make the problem of agent trust *legible* — to show that the question "how do I know the agent didn't cheat?" has a structure, and that cryptographic primitives already used in other domains (HMAC, Merkle chains, commitment schemes) can be mapped onto it. The layers here are working implementations of those ideas, not hardened production tooling.

### The key is only as safe as your machine

The HMAC key is stored as a file on the researcher's machine. Since the agent runs as the same user, it could in principle locate the key, re-run `trust init`, regenerate the manifest to match tampered files, and commit the new manifest. `trust verify` would then pass.

This is a known limitation, not an oversight. Closing it fully would require:
- Storing the key in a system keychain (macOS Keychain, OS credential store) so programmatic access from a subprocess is restricted
- Or signing with a hardware security key (YubiKey) that cannot be read from software
- Or performing the verification step on a separate machine that the agent never touches

Each of these is a real engineering path. This project deliberately stops short of them to keep the code readable and the concepts central.

### Re-running `trust init` is a visible trust reset

If the key is lost or if an agent manages to re-anchor the manifest, the HMAC chain breaks at that point. This event is always visible in `git log` — a new `.trust_manifest.json` commit mid-run is itself a signal worth investigating. The raw SHA-256 hashes in all prior manifest commits remain auditable even without the key.

### The honest ceiling

No software-only solution running as the same OS user can make cheating *impossible*. The value of this layer is not prevention — it is raising the cost and visibility of cheating. An agent that games the metric must now also actively interfere with a separate integrity system, and that interference leaves traces in git history, the ledger, and the statistical audit. The goal is to make silent, undetected gaming structurally harder.

---

## Design principles

**Cryptography makes cheating leave a trace, not impossible.**
The goal is not to prevent a sufficiently capable agent from gaming — it is to ensure that any gaming produces a verifiable, attributable record. This is the same trust model as certificate transparency or git commit signing.

**Each layer patches the blind spot of the one above.**
The manifest stops file tampering, but a clever agent could still overfit to a fixed val set — that is what the isolated evaluator addresses. The evaluator stops data leakage, but the agent could still cherry-pick runs — that is what the ledger addresses. No single layer is sufficient alone.

**The secret key never leaves the researcher's machine.**
The HMAC key is the root of trust. It is generated locally, stored at `.trust_key` (gitignored), and never transmitted. If you lose it, run `trust init` again to re-anchor. The worst an agent can do without the key is break verification — it cannot silently pass it.
