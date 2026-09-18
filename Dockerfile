FROM python:3.11-slim

# tshark is the only external process the pipeline shells out to (CLAUDE.md).
# Without it the image can serve /detect but every /capture/* call fails at
# runtime with "tshark not found in PATH".
# DEBIAN_FRONTEND=noninteractive keeps the wireshark-common postinst from
# blocking on its "should non-root users capture?" prompt.
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends tshark \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements first for layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir --default-timeout=600 -r requirements.txt

# Copy application code
COPY igu_sentinel/ /app/igu_sentinel/
COPY tests/fixtures/ /app/tests/fixtures/
# Trained model artifacts. Without these the service starts but every scoring
# call raises "model not available" — the detectors load from models/ at import.
COPY models/ /app/models/

# Run as a non-root user. The container previously ran as root for no reason:
# nothing in the service needs privilege, and root plus a mounted source tree
# means a bug in the API is a host-level problem.
RUN useradd --system --create-home --uid 10001 sentinel \
    && chown -R sentinel:sentinel /app
USER sentinel

# Health check
HEALTHCHECK --interval=5s --timeout=3s --start-period=10s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8000/health', timeout=2)"

# Run sentinel FastAPI app
CMD ["uvicorn", "igu_sentinel.api:app", "--host", "0.0.0.0", "--port", "8000"]
