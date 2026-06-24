# ── Stage 1: PyArmor obfuscation ──────────────────────────────────────────────
FROM python:3.11-slim AS obfuscate

RUN pip install --no-cache-dir "pyarmor==7.*"

WORKDIR /src
COPY *.py ./

# Obfuscate all Python source files into /dist (PyArmor 7 — no license required)
RUN mkdir /dist && pyarmor obfuscate --output /dist --exact *.py

# ── Stage 2: Runtime image ─────────────────────────────────────────────────────
FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        openssl libssl-dev gcc python3-dev \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
        paramiko==3.* \
        requests==2.* \
        cryptography==42.*

WORKDIR /app

# Copy obfuscated Python files from stage 1
COPY --from=obfuscate /dist/ ./

# Copy non-Python assets
COPY entrypoint.sh ./
RUN chmod +x entrypoint.sh

# Data volume for events, samples, certs, license token
VOLUME ["/data"]

ENTRYPOINT ["./entrypoint.sh"]
