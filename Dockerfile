# HoneyTwin twin container image. One image serves every twin; the
# per-twin behavior comes from the config file mounted at runtime (see
# design.md's "Twin container image" decision) rather than being baked
# in at build time.

FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml uv.lock README.md ./
COPY src ./src

RUN pip install --no-cache-dir .

RUN useradd --create-home --uid 10001 honeytwin
USER honeytwin

ENTRYPOINT ["python", "-m", "honeytwin.runtime", "--config", "/etc/honeytwin/twin.json"]
