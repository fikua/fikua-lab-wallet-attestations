FROM golang:1.26-alpine AS build
WORKDIR /src
RUN apk add --no-cache ca-certificates
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/wallet-attestations ./cmd/wallet-attestations

FROM scratch
# Needed for outbound HTTPS to the Fikua DSS (CSC v2.0 signing calls) —
# this service makes outbound TLS calls, so it can't skip CA certs.
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/wallet-attestations /wallet-attestations
EXPOSE 8080
ENTRYPOINT ["/wallet-attestations"]
