#!/bin/sh
set -eu

install -m 0644 /solution/decoder.py /app/relayframe/decoder.py
printf '%s\n' "Installed the reference RelayFrame decoder at /app/relayframe/decoder.py"
