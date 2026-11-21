FROM golang:1.26-alpine AS build
WORKDIR /src
RUN apk add --no-cache ca-certificates
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/wallet-attestations ./cmd/wallet-attestations
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/healthcheck ./cmd/healthcheck

FROM scratch
# Needed for outbound HTTPS to the Fikua DSS (CSC v2.0 signing calls) —
# this service makes outbound TLS calls, so it can't skip CA certs.
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/wallet-attestations /wallet-attestations
COPY --from=build /out/healthcheck /healthcheck
EXPOSE 8080
# GET /health (OBS-17, DEP-10). Traefik routes only to healthy containers:
# --start-interval makes a new one healthy seconds after it is ready.
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --start-interval=2s --retries=3 CMD ["/healthcheck"]
ENTRYPOINT ["/wallet-attestations"]
