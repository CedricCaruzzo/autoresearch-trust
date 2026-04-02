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

### Layer 2 — Ledger (coming in Phase 3)

**File:** `ledger.py`
**Threat addressed:** #4

An append-only SQLite log where each entry is chained to the previous one via a Merkle hash. Every experiment run — whether it improved the metric or not — is recorded before the result is known. Deleting or rewriting entries breaks the chain and is immediately detectable.

---

### Layer 3 — Isolated Evaluator (coming in Phase 4)

**File:** `evaluator.py`
**Threat addressed:** #3

Runs the evaluation in an isolated subprocess that has no write access to the data or evaluation scripts. Injects a random nonce into each evaluation run, so the agent cannot overfit to a fixed validation set over many iterations.

---

### Layer 4 — Hypothesis Logger (coming in Phase 5)

**File:** `hypothesis.py`
**Threat addressed:** #5

Before each experiment runs, the agent must emit a structured prediction: what it expects to change and why. This prediction is committed to the ledger before the result is known. An agent that is genuinely discovering improvements will show correlated predictions and results. An agent that is gaming will show decoupled noise in predictions but suspiciously clean results — a statistically detectable signature.

---

### Layer 5 — Statistical Auditor (coming in Phase 6)

**File:** `auditor.py`
**Threat addressed:** #4 and #5 in aggregate

Analyses the full run history for anomaly patterns: improvement rates that exceed theoretical bounds, prediction accuracy that is too low (post-hoc rationalisation) or too high (suspiciously well-calibrated), and distribution of keep/discard decisions.

---

## Design principles

**Cryptography makes cheating leave a trace, not impossible.**
The goal is not to prevent a sufficiently capable agent from gaming — it is to ensure that any gaming produces a verifiable, attributable record. This is the same trust model as certificate transparency or git commit signing.

**Each layer patches the blind spot of the one above.**
The manifest stops file tampering, but a clever agent could still overfit to a fixed val set — that is what the isolated evaluator addresses. The evaluator stops data leakage, but the agent could still cherry-pick runs — that is what the ledger addresses. No single layer is sufficient alone.

**The secret key never leaves the researcher's machine.**
The HMAC key is the root of trust. It is generated locally, stored at `.trust_key` (gitignored), and never transmitted. If you lose it, run `trust init` again to re-anchor. The worst an agent can do without the key is break verification — it cannot silently pass it.
