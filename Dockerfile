FROM python:3.11-slim

WORKDIR /app

# Copy requirements first for layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY igu_sentinel/ /app/igu_sentinel/
COPY tests/fixtures/ /app/tests/fixtures/

# Health check
HEALTHCHECK --interval=5s --timeout=3s --start-period=10s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8000/health', timeout=2)"

# Run sentinel FastAPI app
CMD ["uvicorn", "igu_sentinel.api:app", "--host", "0.0.0.0", "--port", "8000"]
