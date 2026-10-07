# Contributing

## Setup

```bash
git clone https://github.com/mohamed-alired/drf-totp.git
cd drf-totp
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Checks

```bash
ruff check src tests
ruff format src tests
pytest --cov
DJANGO_SETTINGS_MODULE=tests.settings PYTHONPATH=src:. python -m django makemigrations drf_totp --check --dry-run
```

CI runs the same commands across Python 3.9–3.13 and Django 4.2/5.1/5.2.

## Guidelines

- Keep views thin; business rules live in `drf_totp/services.py`.
- New settings go in `drf_totp/conf.py` with a default and a comment, and in
  the README settings table.
- Model changes need a migration (`python -m django makemigrations drf_totp`
  with the settings above) and a CHANGELOG entry.
- Tests use frozen time (`frozen` fixture) so codes are deterministic.
- Anything security related: add a test that fails without the change.

## Releasing

1. Update `__version__` in `src/drf_totp/__init__.py` and `CHANGELOG.md`.
2. Merge to `main`. Once CI succeeds, the release workflow publishes the new
   version to PyPI (using the `PYPI_API_TOKEN` secret; a version that already
   exists is skipped) and creates the `v<version>` GitHub release from the
   CHANGELOG section.
