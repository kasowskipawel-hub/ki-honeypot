FROM python:3.12-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends openssl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# On-box static triage: YARA always; capa (flare-capa) best-effort (heavier).
RUN pip install --no-cache-dir yara-python paramiko \
 && (pip install --no-cache-dir flare-capa || echo "capa skipped")

WORKDIR /app
COPY *.py *.yar entrypoint.sh /app/
RUN chmod +x /app/entrypoint.sh

ENV EVENTS=/data/events.jsonl \
    SAMPLE_DIR=/data/samples \
    CERT=/data/cert.pem \
    KEY=/data/key.pem

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["python", "honeypot.py"]
