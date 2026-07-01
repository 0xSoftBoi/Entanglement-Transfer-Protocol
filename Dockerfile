# ETP Custody Cloud — service container.
#
#   docker build -t etp-custody-cloud .
#   docker run -e ETP_CLOUD_ADMIN_TOKEN=… -e ETP_CLOUD_HOST=0.0.0.0 \
#              -v custody-data:/data -e ETP_CLOUD_DB=/data/custody.db \
#              -p 8080:8080 etp-custody-cloud
#
# The same image runs the anchor worker on a schedule:
#   docker run … etp-custody-cloud python -c "…AnchorWorker…run_once()"
# (production wiring in docs/cloud/CUSTODY_CLOUD_DESIGN.md §11)

FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/

# Real post-quantum crypto is required for the service (keys must be portable).
RUN pip install --no-cache-dir ".[crypto]"

ENV ETP_CLOUD_HOST=0.0.0.0 \
    ETP_CLOUD_PORT=8080 \
    ETP_CLOUD_DB=/data/custody.db
VOLUME /data
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s \
  CMD python -c "import urllib.request,os;urllib.request.urlopen(f'http://127.0.0.1:{os.environ[\"ETP_CLOUD_PORT\"]}/healthz',timeout=2)"

CMD ["python", "-m", "ltp.cloud.service"]
