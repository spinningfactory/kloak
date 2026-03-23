FROM python:3.11-slim

WORKDIR /app

# openssl CLI needed to generate self-signed certs for the echo server
RUN apt-get update && apt-get install -y --no-install-recommends openssl && rm -rf /var/lib/apt/lists/*

COPY app.py .

CMD ["python", "-u", "app.py"]
