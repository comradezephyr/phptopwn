# PHP2Shell honeypot sensor
# Deliberately *not* based on php/apache images: only the wire behaviour is emulated.
#
# Stage 1 builds a wheel; stage 2 installs it into a clean runtime image, so
# build tooling and source never ship in the final layer.
FROM python:3.12-slim AS build

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1

COPY . /src
WORKDIR /src
RUN pip install --upgrade build \
    && python -m build --wheel --outdir /wheelhouse


FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PHPTOPWN_HTTP_PORT=8080 \
    PHPTOPWN_TLS_PORT=8443

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 1000 phptopwn \
    && useradd --system --uid 1000 --gid phptopwn --home-dir /app --shell /usr/sbin/nologin phptopwn

COPY --from=build /wheelhouse/*.whl /tmp/
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 0755 /usr/local/bin/entrypoint.sh \
    && pip install --no-cache-dir /tmp/phptopwn-*.whl \
    && rm /tmp/*.whl \
    && mkdir -p /app/logs /app/captured_payloads /app/certs \
    && chown -R phptopwn:phptopwn /app

WORKDIR /app
USER phptopwn

EXPOSE 8080 8443 9091

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import sys,urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:9091/healthz', timeout=2).status == 200 else 1)"

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
