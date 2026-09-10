# Pinned to 3.11-slim-bookworm to match CI/CD container and address CVEs in
# OpenSSL, systemd, Kerberos and other packages present in older base images.
# Update this tag intentionally — do not use a floating `python:3` tag.
FROM python:3.11-slim-bookworm

LABEL maintainer="squad:git-defenders" url="https://github.com/IBM/detect-secrets"

RUN \
  apt-get update && \
  apt-get -y remove --purge mysql* && \
  apt-get upgrade -y && \
  apt-get install -y --no-install-recommends git && \
  rm -rf /var/lib/apt/lists/* && \
  pip install --upgrade pip
