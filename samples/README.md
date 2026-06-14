# Samples

Synthetic fixtures for trying and testing Vault. **Nothing here is a real credential** — every
value is randomly generated and marked `FAKE`/`EXAMPLE`.

## `keys.txt`

A deliberately messy, semi-structured secrets file — the kind a developer accumulates: a mix of
`KEY=value`, `key: value`, bare tokens with no label, provider-prefixed secrets (`ghp_`, `sk-`,
`AKIA`, `glpat-`, `AGE-SECRET-KEY-`, `xoxb-`), blocks separated by blank lines and `---` rulers,
`#` comments, and a weak passphrase. It exercises the lenient `import --format raw` parser.

```sh
vault init                              # create an empty vault
vault import --format raw samples/keys.txt   # parse, review (masked), and store encrypted
vault ls --search github                # find it
vault get github                        # copy the secret to the clipboard (model-blind)
```

## Ground rules (OSS hygiene)

- **Never commit real secrets.** This file is safe only because its values are synthetic.
- The repo's `.gitignore` ignores real vault artifacts (`*.vlt`, `*.state`) and the project
  toolchain; sample text files are intentionally committed.
- If you adapt this for your own data, do it **outside** the repo and keep it out of version
  control.
