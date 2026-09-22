FROM docker.io/library/python:3.12.14-slim@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

COPY relayframe /app/relayframe
COPY examples /app/examples

RUN mkdir -p /app/test_output \
    && chmod -R a=rX /app/relayframe /app/examples \
    && chmod a+w /app/relayframe /app/relayframe/decoder.py

WORKDIR /app
