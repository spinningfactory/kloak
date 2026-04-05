FROM python:3.13-alpine
RUN apk add --no-cache openssl
COPY server.py /server.py
EXPOSE 8443
ENTRYPOINT ["python3", "-u", "/server.py"]
