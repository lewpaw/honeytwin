# HoneyTwin

nmap-scan-driven honeypot twin generator. See [docs/PRD.md](docs/PRD.md) and
[docs/ROADMAP.md](docs/ROADMAP.md) for product scope and phased plan.

## Development

```
py -m uv sync
py -m uv run pytest -m "not integration"
py -m uv run ruff check .
py -m uv run ruff format --check .
```
