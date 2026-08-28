# Stage 1 — install locked runtime deps.
# This layer is cached until requirements/prod.txt changes; no other file busts it.
# requirements/prod.txt is a pip-compile locked file — fully self-contained,
# no constraints file needed at install time.
FROM python:3.12-slim AS deps
WORKDIR /app
COPY requirements/prod.txt requirements/prod.txt
RUN pip install --no-cache-dir -r requirements/prod.txt

# Stage 2 — runtime image.
# Carries the installed packages forward, then adds source + registers the package.
# Mirrors the nixpacks buildCommand exactly:
#   pip install -r requirements/prod.txt && pip install . --no-deps
FROM python:3.12-slim AS runtime
WORKDIR /app
COPY --from=deps /usr/local/lib/python3.12/site-packages \
                 /usr/local/lib/python3.12/site-packages
COPY --from=deps /usr/local/bin /usr/local/bin
# Copy source, then register the acpsec package (no-deps: all deps already in
# site-packages from the deps stage). WORKDIR /app is first in sys.path so
# acpsec_api imports resolve to /app/acpsec_api — which makes
# Path(__file__).parent.parent / "data" resolve to /app/data at runtime.
COPY . .
RUN pip install --no-cache-dir --no-deps . \
    && useradd -r -s /bin/false -u 1001 appuser \
    && chown -R appuser /app
USER appuser
# PORT is injected by Railway at container start — never a build-time ARG or ENV.
CMD ["sh", "-c", "uvicorn acpsec_api.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
