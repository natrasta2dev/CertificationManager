FROM python:3.11-slim AS base

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    openssl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY pyproject.toml setup.py README.md generate_test_certificates.py seed_presentation.py ./
COPY src/ src/

RUN pip install --no-cache-dir -e .

RUN useradd -m -u 1000 certmanager
RUN mkdir -p /data/.certmanager && chown -R certmanager:certmanager /data

USER certmanager

ENV CERTMANAGER_STORAGE_PATH=/data/.certmanager
ENV CERTMANAGER_HOST=0.0.0.0
ENV CERTMANAGER_PORT=8000

EXPOSE 8000

VOLUME ["/data/.certmanager"]

CMD ["certmanager", "web", "--host", "0.0.0.0", "--port", "8000"]
