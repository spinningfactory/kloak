FROM python:3.11-slim

WORKDIR /app

# Install requests
RUN pip install --no-cache-dir requests
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

# Copy application
COPY app.py .
COPY entrypoint.sh .

# Use shell entrypoint to exercise exec tracepoint detection.
# At container start, PID 1 is /bin/sh (no TLS symbols). Python
# starts via exec, triggering sched_process_exec for uprobe attachment.
ENTRYPOINT ["/bin/sh", "/app/entrypoint.sh"]
