FROM docker.io/library/python:3.12.14-slim@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONNOUSERSITE=1

COPY contract/relayframe /opt/relay-contract/relayframe
COPY candidate_host.py /opt/relay-runner/candidate_host.py
COPY verifier.py /tests/verifier.py
COPY test.sh /tests/test.sh

RUN mkdir -p /app/relayframe /logs/verifier \
    && chmod 0755 /opt /opt/relay-contract /opt/relay-contract/relayframe /opt/relay-runner \
    && chmod 0644 /opt/relay-contract/relayframe/*.py /opt/relay-runner/candidate_host.py \
    && chmod 0700 /tests \
    && chmod 0700 /tests/test.sh \
    && chmod 0600 /tests/verifier.py \
    && chmod 0700 /logs/verifier

WORKDIR /tests
