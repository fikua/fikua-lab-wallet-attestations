# Contributing

## Before opening a PR

- `go build ./...`, `go vet ./...`, and `gofmt -l .` must be clean.
- `go test ./...` must pass.
- This service's whole purpose is ARF/eIDAS conformance for the Wallet
  Provider role — changes to the WIA's claims, headers, or signing
  mechanism should cite the ARF/HAIP section they follow.

## Versioning

Tagged releases (`vX.Y.Z`) trigger `release.yml`, which builds and
publishes `fikua/fikua-lab-wallet-attestations` to Docker Hub.

## Reporting issues

Open a GitHub Issue on this repo.
