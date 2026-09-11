# fikua-lab-wallet-attestations

Fikua Lab acting as an ARF **Wallet Provider**: issues Wallet Instance
Attestations (WIA) for EUDI Wallet instances.

Standalone Go service (single binary), a port of `fikua-lab`'s Java
`fikua-wallet-provider` module. Signs every WIA via the [Fikua Digital
Signature Service](https://github.com/fikua/fikua-digital-signature-service)
(CSC v2.0), using [`fikua-dss-csc-client-go`](https://github.com/fikua/fikua-dss-csc-client-go) —
unlike the Java version, which signed with a local PEM key.

## ARF terminology: WUA, WIA, and Key Attestation

Per the EUDI Wallet [Architecture and Reference Framework](https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework)
and its Technical Specification 3 ("Specification of Wallet Unit
Attestations"):

- **WUA (Wallet Unit Attestation)** is the umbrella term for the
  attestation(s) a Wallet Provider issues about a Wallet Unit, so
  Issuers and Relying Parties can check the wallet's authenticity,
  security level, and revocation status.
- A WUA is made of **two distinct attestation types**:
  - **WIA (Wallet Instance Attestation)** — attests to the integrity
    and authenticity of the wallet *application instance* (a genuine,
    unmodified build from a known Wallet Provider, running on a
    trustworthy device).
  - **KA (Key Attestation)** — attests to the security of the
    cryptographic keys held in the wallet's secure hardware (WSCD).

**This service issues only the WIA half.** It does not issue Key
Attestations. "WIA," not the broader "WUA," is therefore the accurate
name for what it does today — hence the repo is named
`wallet-attestations` (generic enough to grow into full WUA issuance
later) rather than claiming WUA support it doesn't have yet.

## What lives here

```text
.
├── cmd/wallet-attestations   main() — wires config, DSS signing key, HTTP routes
├── internal/config           environment-variable configuration
├── internal/httpapi          HTTP handlers (issue-wia, attestation/status, health)
└── internal/walletprovider   WIA issuance logic + DSS-backed signing key
```

## API

Paths match the Java service's, so `fikua-lab-wallet` needs no
client-side change beyond pointing its `WALLET_PROVIDER_BASE` at this
service:

- `POST /wallet-provider/issue-wia`
  Body: `{"client_id": "...", "jwk": {EC P-256 public key}}`.
  Returns `{"wia": "<signed WIA JWT>", "expires_in": 86400}`. The WIA is
  signed by this Wallet Provider's DSS-held key (`typ:
  wallet-attestation+jwt`, `x5c` chain to the Fikua DSS mock TSP root),
  with `cnf.jwk` binding the wallet's own proof-of-possession key.
- `GET /wallet-provider/attestation/status?id=<client_id>`
  Mock revocation status — ported faithfully from the Java service,
  which always returns `"status": "valid"`. There is no real revocation
  tracking in this lab service.
- `GET /health` — health check.

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `ADDR` | `:8080` | listen address |
| `FIKUA_BASE_URL` | `https://wallet-attestations.fikua.com` | this Wallet Provider's own identifier (`iss` of every WIA) |
| `FIKUA_DSS_URL` | *(required)* | Fikua DSS base URL |
| `FIKUA_DSS_CLIENT_ID` | *(required)* | this tenant's CSC v2.0 OAuth2 client id |
| `FIKUA_DSS_CLIENT_SECRET` | *(required)* | this tenant's CSC v2.0 OAuth2 client secret |
| `FIKUA_DSS_WALLET_PROVIDER_CREDENTIAL_ID` | `fikua-wallet-provider-001` | this tenant's DSS signing credential id |
| `FIKUA_DSS_CREDENTIAL_PASSWORD` | *(required)* | this tenant's DSS credential password |

There is no local-PEM fallback and no ephemeral key: a WIA an Issuer has
never seen a wallet instance for is exactly the kind of eIDAS-relevant
signature that belongs in the DSS's HSM behind a real certificate — see
`internal/walletprovider/signingkey.go`'s doc comment. A misconfigured or
unreachable DSS fails this service at boot.

## Build

```sh
go build ./cmd/wallet-attestations
```

## License

Apache-2.0. See [LICENSE](LICENSE).
