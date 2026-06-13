# Activate the project-scoped Rust toolchain for the current shell.
# SOURCE this from the repo root (do not execute):   . scripts/dev-env.sh
#
# It points RUSTUP_HOME / CARGO_HOME at ./.toolchain (git-ignored) and prepends the project's
# cargo bin to PATH, so `cargo`/`rustc`/`clippy` resolve to the in-project toolchain and nothing
# machine-wide is used. Run ./scripts/setup-rust.sh once first.

if [ ! -d "$PWD/.toolchain/cargo/bin" ]; then
  echo "dev-env: ./.toolchain not found — run ./scripts/setup-rust.sh first (from the repo root)." >&2
else
  export RUSTUP_HOME="$PWD/.toolchain/rustup"
  export CARGO_HOME="$PWD/.toolchain/cargo"
  export PATH="$CARGO_HOME/bin:$PATH"
  echo "dev-env: project toolchain active — $(rustc --version 2>/dev/null)"
fi
