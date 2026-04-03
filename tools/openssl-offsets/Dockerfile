ARG OPENSSL_VERSION=3.5.0

FROM alpine:3.21

ARG OPENSSL_VERSION

RUN apk add --no-cache build-base perl linux-headers curl jq \
    && apk add --no-cache -X https://dl-cdn.alpinelinux.org/alpine/edge/community pahole || true

RUN curl -fsSL "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz" \
    -o /tmp/openssl.tar.gz \
    && mkdir -p /tmp/openssl \
    && tar xzf /tmp/openssl.tar.gz -C /tmp/openssl --strip-components=1

WORKDIR /tmp/openssl

RUN ./Configure \
    --prefix=/usr/local \
    --openssldir=/usr/local/ssl \
    no-shared \
    no-tests \
    no-docs \
    -g -O0 \
    && make -j$(nproc) build_sw

COPY extract_offsets.sh /tmp/extract_offsets.sh
RUN chmod +x /tmp/extract_offsets.sh

ENTRYPOINT ["/tmp/extract_offsets.sh"]
