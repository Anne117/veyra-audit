FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    AUDIT_STORAGE=/data

WORKDIR /app

RUN apt-get update \
 && apt-get install -y --no-install-recommends git \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY templates ./templates

RUN useradd --system --uid 10001 --create-home appuser \
 && mkdir -p /data && chown -R appuser:appuser /data /app
USER appuser

EXPOSE 8090

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8090/healthz',timeout=3)"

CMD ["gunicorn", "--workers", "1", "--threads", "4", "--timeout", "300", \
     "--bind", "0.0.0.0:8090", "app.web:app"]
