// Command wallet-attestations runs Fikua Lab's ARF Wallet Provider role:
// issuing Wallet Instance Attestations (WIA) for EUDI Wallet instances.
package main

import (
	"context"
	"log"
	"net/http"
	"os"

	cscclient "github.com/fikua/fikua-dss-csc-client-go"
	"github.com/fikua/fikua-lab-wallet-attestations/internal/config"
	"github.com/fikua/fikua-lab-wallet-attestations/internal/health"
	"github.com/fikua/fikua-lab-wallet-attestations/internal/httpapi"
	"github.com/fikua/fikua-lab-wallet-attestations/internal/telemetry"
	"github.com/fikua/fikua-lab-wallet-attestations/internal/walletprovider"
)

func main() {
	if health.IsHealthcheck() {
		os.Exit(health.Probe(config.ListenAddr()))
	}
	shutdownTelemetry, telErr := telemetry.Setup(context.Background(), "fikua-lab-wallet-attestations")
	if telErr != nil {
		log.Fatalf("telemetry: %v", telErr)
	}
	defer func() { _ = shutdownTelemetry(context.Background()) }()

	cfg := config.Load()

	signingKey, err := loadSigningKey(cfg)
	if err != nil {
		log.Fatalf("loading WIA signing key: %v", err)
	}
	log.Printf("WIA signing key loaded (kid=%s)", signingKey.KID())

	service := walletprovider.NewService(cfg.BaseURL, signingKey, cfg.WIATTL)

	mux := http.NewServeMux()
	httpapi.NewHandler(service).Routes(mux)

	log.Printf("fikua-lab-wallet-attestations listening on %s (iss=%s)", cfg.Addr, cfg.BaseURL)
	if err := http.ListenAndServe(cfg.Addr, telemetry.HTTPHandler(httpapi.WithCORS(mux))); err != nil {
		log.Fatal(err)
	}
}

// loadSigningKey builds the WIA signing key via the Fikua DSS's CSC API.
// There is no local-PEM fallback and no ephemeral key: see
// walletprovider.SigningKey's doc comment for why a WIA specifically
// needs a DSS-backed, eIDAS-relevant certificate rather than a
// throwaway key nobody trusts. A misconfigured or unreachable DSS fails
// this service at boot.
func loadSigningKey(cfg config.Config) (*walletprovider.SigningKey, error) {
	log.Printf("signing via Fikua DSS at %s (credential=%s)", cfg.DSSURL, cfg.DSSWalletProviderCredentialID)
	client := cscclient.New(cscclient.Config{
		BaseURL:            cfg.DSSURL,
		ClientID:           cfg.DSSClientID,
		ClientSecret:       cfg.DSSClientSecret,
		CredentialID:       cfg.DSSWalletProviderCredentialID,
		CredentialPassword: cfg.DSSCredentialPassword,
	})
	signer, err := cscclient.NewSigner(context.Background(), client)
	if err != nil {
		return nil, err
	}
	leafDER, err := signer.LeafDER(context.Background())
	if err != nil {
		return nil, err
	}
	// Only the leaf goes into x5c — see cscclient.Signer.LeafDER.
	return walletprovider.NewSigningKey(signer, [][]byte{leafDER})
}
