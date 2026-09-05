#!/usr/bin/env bash
# CI helper: pull build dependencies from the internal mirror. Credential
# markers are replaced at run time by tests/detection_corpus.rs.
set -euo pipefail

# RFC 7617 spells the credential base64(user:password), so what a real
# Authorization: Basic header carries is an encoded credential, not a token.
wget -q --header="Authorization: Basic {{B64BASIC_20_531}}" \
  https://artifacts.internal/deps.tar.gz -O deps.tar.gz

# The same header taken from the environment, which is the correct pattern.
wget -q --header="Authorization: Basic ${MIRROR_BASIC_AUTH}" \
  https://mirror.internal/index.json -O index.json

# The expected digest of the archive above: 64 hex characters, not a value.
echo "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08  deps.tar.gz" | sha256sum -c -
