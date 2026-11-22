FROM python:3.12.8-slim

# tzdata so TZ / DIGEST_TIME work; nothing else is needed (stdlib only).
RUN apt-get update && apt-get install -y --no-install-recommends tzdata \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 10001 --create-home epaphras \
    && mkdir /data && chown epaphras /data

WORKDIR /app
COPY epaphras/ epaphras/
USER epaphras
ENV PYTHONUNBUFFERED=1 DATA_DIR=/data
VOLUME ["/data"]
ENTRYPOINT ["python", "-m", "epaphras", "--env", "/dev/null"]
