FROM python:3.11-slim

# openssl CLI needed to generate self-signed certs for the echo server
RUN apt-get update && apt-get install -y --no-install-recommends openssl && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY app.py echo_server.py ./

CMD ["python", "-u", "app.py"]
