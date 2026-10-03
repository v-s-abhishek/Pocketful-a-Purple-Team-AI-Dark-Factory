# Standard library only: no pip install, so the build needs no network
# beyond having the base image available locally.
FROM python:3.11-slim

LABEL org.opencontainers.image.title="pocketful" \
      org.opencontainers.image.version="stage-2"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080 \
    DB_PATH=/data/wallet.db

WORKDIR /srv
COPY app ./app
COPY tests ./tests
COPY attacks ./attacks
# The attack suite inspects the Dockerfile itself (I9), so ship it too.
COPY Dockerfile README.md ./

RUN useradd --system --no-create-home --uid 10001 wallet \
 && mkdir -p /data \
 && chown wallet:wallet /data

USER wallet
VOLUME ["/data"]
EXPOSE 8080

HEALTHCHECK --interval=5s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import os,urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/health' % os.environ['PORT'], timeout=2)"

CMD ["python", "-m", "app"]
