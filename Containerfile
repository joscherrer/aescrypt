FROM registry.access.redhat.com/ubi9/ubi-minimal:9.1 AS vault-builder

ARG VAULT_VERSION=1.13.1
ARG ARCH=amd64

ARG VER_CA_CERTIFICATES=2022.*
ARG VER_OPENSSL=1:3.0.1*
ARG VER_LIBCAP=2.48*
ARG VER_TZDATA=2023c*
ARG VER_UNZIP=6.0*
ARG VER_SHADOW_UTILS=2:4.9*
ARG VER_UTIL_LINUX=2.37*
ARG VAULT_RELEASE_URL=https://releases.hashicorp.com/vault

RUN set -eux; \
    microdnf install -y \
        ca-certificates-${VER_CA_CERTIFICATES} \
        shadow-utils-${VER_SHADOW_UTILS} \
        util-linux-${VER_UTIL_LINUX} \
        openssl-${VER_OPENSSL} \
        libcap-${VER_LIBCAP} \
        tzdata-${VER_TZDATA} \
        unzip-${VER_UNZIP} \
        && \
    mkdir -p /tmp/build && \
    curl -L ${VAULT_RELEASE_URL}/${VAULT_VERSION}/vault_${VAULT_VERSION}_linux_${ARCH}.zip -o /tmp/vault_${VAULT_VERSION}_linux_${ARCH}.zip && \
    unzip -d /tmp/build /tmp/vault_${VAULT_VERSION}_linux_${ARCH}.zip && \
    setcap cap_ipc_lock=+ep /tmp/build/vault && \
    microdnf clean all

FROM registry.access.redhat.com/ubi9/openjdk-17:1.14 AS aescrypt-builder
USER root
COPY . /tmp/build/
WORKDIR /tmp/build
RUN mvn clean compile package


FROM registry.access.redhat.com/ubi9/ubi-minimal:9.1

ARG VER_CA_CERTIFICATES=2022.*
ARG VER_OPENSSL=1:3.0.1*
ARG VER_LIBCAP=2.48*
ARG VER_TZDATA=2023c*
ARG VER_UNZIP=6.0*
ARG VER_SHADOW_UTILS=2:4.9*
ARG VER_UTIL_LINUX=2.37*
ARG VER_OPENJDK_17=17.0.*

COPY --from=vault-builder /tmp/build/vault /usr/local/bin/vault
COPY --from=aescrypt-builder /tmp/build/target/aescrypt-*-dependencies.jar /opt/aescrypt/aescrypt.jar
COPY --from=aescrypt-builder /tmp/build/aescrypt /usr/local/bin/aescrypt

RUN microdnf --setopt=install_weak_deps=0 --setopt=tsflags=nodocs -y install \
        ca-certificates-${VER_CA_CERTIFICATES} \
        shadow-utils-${VER_SHADOW_UTILS} \
        openssl-${VER_OPENSSL} \
        java-17-openjdk-headless-1:${VER_OPENJDK_17} \
        && \
    groupadd --gid 1001 vault && \
    adduser --uid 1001 -g vault vault && \
    microdnf clean all && \
    rm -rf /var/lib/rpm && \
    rm -rf /var/cache/yum && \
    mkdir -p /vault/logs /vault/file /vault/config && \
    chown -R vault:vault /vault && \
    chmod +x /usr/local/bin/aescrypt

USER vault
WORKDIR /vault

EXPOSE 8100
ENTRYPOINT ["vault"]
CMD ["agent"]