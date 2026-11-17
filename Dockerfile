FROM golang:1.26-bookworm AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /microtunnel ./cmd/microtunnel

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    iproute2 curl iputils-ping procps nginx net-tools openssh-client traceroute \
    gnupg2 gettext-base \
    && curl -sL https://apt.envoyproxy.io/signing.key | gpg --dearmor -o /usr/share/keyrings/envoy-keyring.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/envoy-keyring.gpg] https://apt.envoyproxy.io bookworm main" \
       > /etc/apt/sources.list.d/envoy.list \
    && apt-get update && apt-get install -y envoy \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /microtunnel
COPY config/nginx-keepalive.conf /etc/nginx/conf.d/keepalive.conf
COPY scripts/docker-entrypoint.sh scripts/microtunnel-create-tunnel.sh config/envoy.yaml.tmpl config/index.html.tmpl ./
COPY --from=builder /microtunnel ./
COPY config/ ./config/

ENTRYPOINT ["./docker-entrypoint.sh"]
