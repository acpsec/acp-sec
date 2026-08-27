FROM python:3.12-slim
WORKDIR /app

# Install locked production dependencies first.
# Layer is cached until requirements/prod.txt changes.
COPY requirements/prod.txt ./requirements/
RUN pip install --no-cache-dir -r requirements/prod.txt

# Copy source and register the package (editable so __file__-relative paths
# such as data/reports and data/leaderboard.json resolve against /app, not
# the site-packages directory).
COPY . .
RUN pip install --no-cache-dir --no-deps -e .

# Non-root runtime user — /app is writable for leaderboard + scan-store writes.
RUN useradd -r -s /bin/false -u 1001 appuser \
    && chown -R appuser /app
USER appuser

# PORT is injected by Railway at container start — never an ARG or build-time ENV.
CMD ["sh", "-c", "uvicorn acpsec_api.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
