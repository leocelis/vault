# Guide — Park your `keys.txt` on Google Drive / a droplet, safely

> Audience: someone who has a messy `keys.txt` and wants **one encrypted file** they can drop on
> storage they don't fully trust (Google Drive, Dropbox, a VPS/droplet, a git repo) — readable only
> with Vault, and tamper-evident.
>
> This is a user-facing walkthrough. The authority is the tech spec
> [UC-07](../specs/UC-07-untrusted-storage-sync.md) (untrusted storage) + [UC-17](../specs/UC-17-quick-capture-raw-import.md)
> (import) and the testable constraints in [`vault_intent.yaml`](../../vault_intent.yaml).

## The 60-second version

```sh
vault init                              # pick a master password (do NOT lose it)
vault import --format raw keys.txt      # review the masked list → confirm
cp ~/.vault/vault.vlt  ~/Drive/vault.vlt   # the .vlt is the only thing you upload
```

That `vault.vlt` is a single opaque blob. Upload it anywhere. To use it elsewhere:

```sh
vault --vault ~/Drive/vault.vlt get github   # prompts for your master password, copies the secret
```

The desktop app does the same: open it, drag `keys.txt` onto the window, then search and copy.

## What you are (and aren't) protected against

| You're safe from… | Why | Constraint |
|---|---|---|
| The backend (or anyone who grabs the file) **reading** your secrets | Whole file is one AEAD blob; the data key is wrapped by your Argon2id-stretched password and never stored in the clear. Every field — even URLs and titles — is inside the encryption | C1, C5, C18 |
| The backend **altering** the file undetectably (bit-flips, splicing, truncation, KDF-downgrade) | Keyed header HMAC + per-block encrypt-then-MAC + per-chunk AEAD tags. Any change makes it fail to open — loudly, not silently | C9, C10, C1 |
| The backend serving you an **older copy** (rollback) | A local, non-synced anchor records the highest version this machine has seen; opening an older one warns (and on a pipe, exits with code `2`) | C16 |

| You're **not** protected from… | What to do |
|---|---|
| The backend **deleting / corrupting-to-garbage** the file (availability) | Keep your own copy. Vault guarantees confidentiality + tamper-*evidence*, not that a vandal can't destroy the file. |
| The backend learning **metadata**: file size (≈ how many entries), how often you save, timestamps | Turn on **size-padding** — `vault pad on` (or the desktop app's **"Pad size"** toggle) — to bucket the file size with Padmé (`≤ ~12 %` overhead), so the size leaks only `O(log log L)` bits (UC-07 §3.2). Save frequency / timestamps still leak. |
| **Forgetting your master password** | There is no recovery. The whole design assumes the blob will be stolen, so there is no backdoor. |

## Rollback detection in practice (C16)

Vault keeps an 8-byte "last version I saw" file **outside** the synced folder:

- Linux `~/.local/share/vault/<id>.state` · macOS `~/Library/Application Support/vault/<id>.state` · Windows `%LOCALAPPDATA%\vault\<id>.state`

If your cloud serves an older vault than this machine last saw:

```
WARNING: vault version regressed (expected >= 7, got 5). The sync backend may have served an older copy.
Proceed anyway? [y/N]
```

- On a terminal: default is **No** (abort).
- Non-interactively (scripts/CI): **no prompt**, exit code **2** (reserved for rollback). Use
  `vault --allow-rollback …` to proceed anyway (the anchor is not lowered).
- **Fresh machine, first open:** there's no anchor yet, so any valid version is trusted
  (trust-on-first-use). To pin a floor when provisioning a new machine:
  `vault --expect-min-version 7 get …`. This residual risk is listed in
  [docs/THREAT_MODEL.md](../THREAT_MODEL.md).

## If you use Git as the backend

- `.gitattributes` already marks `*.vlt binary` (no textual diff/merge — a forced text merge of two
  vaults produces garbage that fails verification).
- Every save rewrites the whole blob (fresh `nonce_prefix`/`master_seed`), so commits are
  whole-file binary changes — use a dedicated repo and `git gc` occasionally.
- `git commit -S` (signed) plus pinning the last-seen commit hash is an optional belt-and-braces
  layer on top of C16.
