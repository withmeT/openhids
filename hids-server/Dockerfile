FROM rust:1.90-bookworm AS builder
WORKDIR /src

COPY Cargo.toml Cargo.lock ./
COPY hids-common ./hids-common
COPY hids-protocol ./hids-protocol
COPY hids-server ./hids-server

RUN cargo build --manifest-path hids-server/Cargo.toml --release

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --home /var/lib/hids-server --create-home --shell /usr/sbin/nologin hids

WORKDIR /app
COPY --from=builder /src/hids-server/target/release/hids-server /usr/local/bin/hids-server
COPY --from=builder /src/hids-server/static /app/static
COPY --from=builder /src/hids-server/rules /app/rules
COPY --from=builder /src/hids-server/elasticsearch /app/elasticsearch
COPY --from=builder /src/hids-server/agent-config.example.json /etc/hids/agent-config.json

RUN mkdir -p /var/lib/hids-server/spool /app/releases /etc/hids \
    && chown -R hids:hids /var/lib/hids-server /app/releases /etc/hids

USER hids
ENV BIND_ADDR=0.0.0.0:8000 \
    ES_URL=http://elasticsearch:9200 \
    STATIC_DIR=/app/static \
    THREAT_RULES_PATH=/app/rules/threat-rules.yaml \
    SPOOL_DIR=/var/lib/hids-server/spool \
    AGENT_RELEASES_DIR=/app/releases \
    AGENT_CONFIG_PATH=/etc/hids/agent-config.json

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8000/healthz >/dev/null || exit 1

CMD ["/usr/local/bin/hids-server"]
