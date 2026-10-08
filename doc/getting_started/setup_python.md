# Python Environment Setup

Anything you build or test with Bazel brings its own Python, so this is only needed for the tools that run outside it, such as `util/dvsim/dvsim.py`, `util/regtool.py` and the other generators.

Install their dependencies into a virtual environment with [uv](https://docs.astral.sh/uv/):

```sh
cd $REPO_TOP
uv sync
```

This creates `$REPO_TOP/.venv` from [`uv.lock`](../../uv.lock), the lock file Bazel also resolves from, using the Python version pinned in [`.python-version`](../../.python-version).
On macOS, install uv with `brew install uv`.
On Ubuntu, follow the [uv installation guide](https://docs.astral.sh/uv/getting-started/installation/).

Re-activate the environment with `source $REPO_TOP/.venv/bin/activate` whenever you return to the repository, or activate it from your shell rc file (e.g. bashrc, cshrc, zshrc).
