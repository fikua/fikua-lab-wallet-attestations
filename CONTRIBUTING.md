# Contributing

## Before opening a PR

- `go build ./...`, `go vet ./...`, and `gofmt -l .` must be clean.
- `go test ./...` must pass.
- This service's whole purpose is ARF/eIDAS conformance for the Wallet
  Provider role — changes to the WIA's claims, headers, or signing
  mechanism should cite the ARF/HAIP section they follow.

## Versioning

Releases (`gh release create vX.Y.Z`) trigger `ci.yml`, which publishes
`ghcr.io/fikua/fikua-lab-wallet-attestations:X.Y.Z`. Deploying it is a
Dependabot pull request in `fikua-platform-iac` (fikua-docs ADR 0019).

## Reporting issues

Open a GitHub Issue on this repo.
