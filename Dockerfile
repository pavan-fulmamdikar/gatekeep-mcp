FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY pyproject.toml README.md LICENSE-MIT LICENSE-APACHE ./
COPY gatekeep ./gatekeep

RUN pip install --upgrade pip \
    && pip install ".[all]" \
    && useradd --create-home --shell /bin/sh gatekeep \
    && mkdir -p /data \
    && chown -R gatekeep:gatekeep /app /data

USER gatekeep
EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2).read()" || exit 1

ENTRYPOINT ["gatekeep"]
CMD ["--help"]
