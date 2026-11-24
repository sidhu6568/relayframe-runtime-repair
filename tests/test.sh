#!/bin/sh
set -u

mkdir -p /logs/verifier
chmod 0700 /logs/verifier
rm -f /logs/verifier/reward.json /logs/verifier/reward.txt

if python3 -E -s /tests/verifier.py; then
    printf '1\n' > /logs/verifier/reward.txt
else
    printf '0\n' > /logs/verifier/reward.txt
fi

chmod 0600 /logs/verifier/reward.txt /logs/verifier/metrics.json 2>/dev/null || true
exit 0
