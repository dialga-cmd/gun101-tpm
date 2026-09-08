# Build Guide

GUN-101-TPM is a Python package built with the standard PEP 517 interface,
using setuptools as its build backend.

## Requirements

- Python 3.9 or newer
- `pip`
- The FLOSS PyPA `build` package

Runtime dependencies are declared in `pyproject.toml`. The optional `tpm`
extra installs `tpm2-pytss` on Linux. Development tools are available through
the `dev` extra.

## Build from source

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip build
python -m build --wheel --sdist
```

The resulting wheel and source archive are written to `dist/`. The same build
command runs in the GitHub Actions quality workflow and the PyPI publishing
workflow.

## Install for development

```bash
python -m pip install -e ".[dev]"
python -m pytest tests/ -v
```

The Linux TPM backend additionally requires a TPM 2.0 device or `swtpm` and
the optional `tpm` extra. Hardware-dependent tests document their requirements
in [CONTRIBUTING.md](../CONTRIBUTING.md).