# PHP2Shell threat-intelligence honeypot
# Deliberately *not* based on php/apache: only the wire behaviour is emulated.
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    HONEYPOT_HTTP_PORT=8080 \
    HONEYPOT_HTTPS_PORT=8443

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 1000 honeypot \
    && useradd --system --uid 1000 --gid honeypot --home-dir /app --shell /usr/sbin/nologin honeypot

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py ./
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 0755 /usr/local/bin/entrypoint.sh \
    && mkdir -p /app/logs /app/captured_payloads /app/certs \
    && chown -R honeypot:honeypot /app

USER honeypot

EXPOSE 8080 8443

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import sys,urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2).status == 200 else 1)"

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
