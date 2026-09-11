// Package config loads this service's configuration from environment
// variables.
package config

import (
	"os"
	"time"
)

// Config holds the Wallet Provider's runtime configuration.
type Config struct {
	Addr string
	// BaseURL is this Wallet Provider's own identifier — the `iss` of
	// every Wallet Instance Attestation (WIA) it issues.
	BaseURL string
	// WIATTL is how long an issued WIA remains valid. ARF leaves this to
	// the Wallet Provider's own policy; 24h matches the Java service this
	// was ported from.
	WIATTL time.Duration
	// DSS* configure the Fikua Digital Signature Service (CSC v2.0)
	// credential every WIA is signed with. An Issuer decides whether to
	// trust a wallet instance based on this signature, so — like
	// fikua-lab-idp's OID4VP Verifier signing key — it belongs in the
	// DSS's HSM behind a real certificate, not a local PEM file. There is
	// no local-key fallback: a self-signed WIA proves nothing an Issuer
	// couldn't have generated itself, so a misconfigured DSS connection
	// fails the service at boot rather than serving attestations nobody
	// should trust.
	DSSURL                        string
	DSSClientID                   string
	DSSClientSecret               string
	DSSWalletProviderCredentialID string
	DSSCredentialPassword         string
}

// Load reads configuration from environment variables, applying defaults
// where unset.
func Load() Config {
	return Config{
		Addr:                          getenv("ADDR", ":8080"),
		BaseURL:                       getenv("FIKUA_BASE_URL", "https://wallet-attestations.fikua.com"),
		WIATTL:                        24 * time.Hour,
		DSSURL:                        getenv("FIKUA_DSS_URL", ""),
		DSSClientID:                   getenv("FIKUA_DSS_CLIENT_ID", ""),
		DSSClientSecret:               getenv("FIKUA_DSS_CLIENT_SECRET", ""),
		DSSWalletProviderCredentialID: getenv("FIKUA_DSS_WALLET_PROVIDER_CREDENTIAL_ID", "fikua-wallet-provider-001"),
		DSSCredentialPassword:         getenv("FIKUA_DSS_CREDENTIAL_PASSWORD", ""),
	}
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
