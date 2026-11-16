// Package walletprovider implements Fikua Lab's role as an ARF Wallet
// Provider: issuing Wallet Instance Attestations (WIA) for wallet
// instances (Wallet Units), per the EUDI Wallet Architecture and
// Reference Framework.
//
// ARF terminology note: a Wallet Unit Attestation (WUA) is the umbrella
// concept covering two distinct attestation types a Wallet Provider
// issues — the Wallet Instance Attestation (WIA, attesting to the
// integrity of the wallet application instance) and a Key Attestation
// (KA, attesting to the security of keys held in the wallet's secure
// hardware). This service issues only the WIA half today; it does not
// issue Key Attestations, so "WIA" — not the broader "WUA" — is the
// accurate name for what it does. See README.md for the full ARF
// reference.
//
// Ported from fikua-lab's Java fikua-wallet-provider module
// (WalletProviderService/WalletProviderController), with one behavior
// change: the signing key now lives in the Fikua DSS (via
// fikua-dss-csc-client-go) rather than a local PEM file — see
// SigningKey's doc comment for why.
package walletprovider

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// WIAType is the JWS "typ" header value a Wallet Instance Attestation
// carries, matching the Java service's wire format so existing wallet
// clients need no change.
const WIAType = "wallet-attestation+jwt"

// Service issues Wallet Instance Attestations.
type Service struct {
	baseURL    string
	signingKey *SigningKey
	ttl        time.Duration
}

// NewService builds a Service. baseURL becomes the `iss` of every WIA it
// issues; ttl is how long an issued WIA remains valid.
func NewService(baseURL string, signingKey *SigningKey, ttl time.Duration) *Service {
	return &Service{baseURL: baseURL, signingKey: signingKey, ttl: ttl}
}

// IssueWIARequest is the wallet-facing request body for POST /issue-wia:
// the wallet instance's own client id and the proof-of-possession public
// key it wants bound into the attestation.
type IssueWIARequest struct {
	ClientID string          `json:"client_id"`
	JWK      json.RawMessage `json:"jwk"`
}

// IssueWIAResult is the response body for POST /issue-wia.
type IssueWIAResult struct {
	WIA       string `json:"wia"`
	ExpiresIn int64  `json:"expires_in"`
	// KeyThumbprint is the RFC 7638 thumbprint of the bound key, for the
	// audit event; never sent to the wallet.
	KeyThumbprint string `json:"-"`
}

// IssueWIA signs and returns a Wallet Instance Attestation for req.
//
// The WIA binds the wallet's own proof-of-possession key via `cnf.jwk`,
// exactly as the Java service did: the wallet later signs a PoP JWT with
// that same key's private half, and whoever checks the WIA can confirm
// the PoP came from the same wallet instance this attestation was issued
// to.
func (s *Service) IssueWIA(req IssueWIARequest) (IssueWIAResult, error) {
	if req.ClientID == "" {
		return IssueWIAResult{}, fmt.Errorf("walletprovider: missing client_id")
	}
	if len(req.JWK) == 0 {
		return IssueWIAResult{}, fmt.Errorf("walletprovider: missing jwk")
	}

	holderKey, err := jwk.ParseKey(req.JWK)
	if err != nil {
		return IssueWIAResult{}, fmt.Errorf("walletprovider: invalid jwk: %w", err)
	}
	holderKeyJSON, err := json.Marshal(holderKey)
	if err != nil {
		return IssueWIAResult{}, fmt.Errorf("walletprovider: re-encoding jwk: %w", err)
	}
	var holderKeyMap map[string]any
	if err := json.Unmarshal(holderKeyJSON, &holderKeyMap); err != nil {
		return IssueWIAResult{}, err
	}

	now := time.Now()
	token, err := jwt.NewBuilder().
		Issuer(s.baseURL).
		Subject(req.ClientID).
		IssuedAt(now).
		Expiration(now.Add(s.ttl)).
		Claim("cnf", map[string]any{"jwk": holderKeyMap}).
		Build()
	if err != nil {
		return IssueWIAResult{}, err
	}

	headers, err := s.wiaHeaders()
	if err != nil {
		return IssueWIAResult{}, err
	}
	signed, err := jwt.Sign(token, jwt.WithKey(s.signingKey.Algorithm(), s.signingKey.Signer(), jws.WithProtectedHeaders(headers)))
	if err != nil {
		return IssueWIAResult{}, err
	}

	thumbprint, err := holderKey.Thumbprint(crypto.SHA256)
	if err != nil {
		return IssueWIAResult{}, err
	}
	return IssueWIAResult{WIA: string(signed), ExpiresIn: int64(s.ttl.Seconds()),
		KeyThumbprint: base64.RawURLEncoding.EncodeToString(thumbprint)}, nil
}

// AttestationStatus is the response body for GET /attestation/status.
//
// This is a mock, faithfully ported from the Java service: every issued
// WIA reports "valid", with no real revocation tracking. A production
// Wallet Provider would track issued attestations and their revocation
// state; this lab service does not.
type AttestationStatus struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

// Status returns the (mock) attestation status for id.
func (s *Service) Status(id string) AttestationStatus {
	return AttestationStatus{ID: id, Status: "valid"}
}

// wiaHeaders builds the JWS protected headers a WIA carries: the typ
// wallets/issuers use to recognize this as a wallet attestation (not some
// other JWT replayed here), the kid, and the x5c chain anchoring this
// Wallet Provider's identity.
func (s *Service) wiaHeaders() (jws.Headers, error) {
	headers := jws.NewHeaders()
	if err := headers.Set(jws.TypeKey, WIAType); err != nil {
		return nil, err
	}
	if err := headers.Set(jws.KeyIDKey, s.signingKey.KID()); err != nil {
		return nil, err
	}
	chain, err := s.signingKey.JOSEX5CChain()
	if err != nil {
		return nil, err
	}
	if chain != nil {
		if err := headers.Set(jws.X509CertChainKey, chain); err != nil {
			return nil, err
		}
	}
	return headers, nil
}
