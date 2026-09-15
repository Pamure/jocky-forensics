# syntax=docker/dockerfile:1
#
# Minimal, reproducible runtime for JOCKY.  The image contains Python, the
# interpreter the fileless mode executes from memory, and openssl for the
# management server's self-signed certificate — nothing else.
#
#   docker build -t jocky .
#   docker run --rm -it --pid=host -v /proc:/proc:ro jocky doctor
#   docker run --rm -it -v "$PWD/case:/case" jocky init /case
#
FROM python:3.12-slim

LABEL org.opencontainers.image.title="jocky" \
      org.opencontainers.image.description="JOCKY forensic scripting runtime (SIH26148)" \
      org.opencontainers.image.licenses="MIT"

# procps is *not* installed on purpose: JOCKY reads /proc directly, and an
# image without ps/ss/lsof proves it at runtime.
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/jocky
COPY pyproject.toml README.md LICENSE ./
COPY jocky ./jocky
RUN pip install --no-cache-dir . \
 && useradd --create-home --uid 10001 analyst
USER analyst
WORKDIR /home/analyst

ENV PYTHONDONTWRITEBYTECODE=1
ENTRYPOINT ["jocky"]
CMD ["--help"]
