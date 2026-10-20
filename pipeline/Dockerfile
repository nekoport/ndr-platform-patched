FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/

# Non-root user; needs read access to /input (ro) and write to /data/state
RUN useradd --system --uid 10001 ndr \
    && mkdir -p /data/state /input \
    && chown -R ndr:ndr /data
USER ndr

ENV PYTHONUNBUFFERED=1 \
    PIPELINE_STATE_DIR=/data/state

CMD ["python3", "-m", "app.main"]
