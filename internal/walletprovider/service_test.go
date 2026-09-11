package walletprovider

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// testSigningKey builds a SigningKey backed by an in-memory EC key and a
// throwaway self-signed certificate, so tests never touch a real DSS.
func testSigningKey(t *testing.T) *SigningKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test wallet provider"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	key, err := NewSigningKey(priv, [][]byte{der})
	if err != nil {
		t.Fatalf("NewSigningKey: %v", err)
	}
	return key
}

func testHolderJWK(t *testing.T) json.RawMessage {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating holder key: %v", err)
	}
	pub, err := jwk.Import(priv.Public())
	if err != nil {
		t.Fatalf("importing holder public key: %v", err)
	}
	raw, err := json.Marshal(pub)
	if err != nil {
		t.Fatalf("marshaling holder key: %v", err)
	}
	return raw
}

func TestIssueWIA(t *testing.T) {
	svc := NewService("https://wallet-attestations.fikua.com", testSigningKey(t), 24*time.Hour)
	holderJWK := testHolderJWK(t)

	result, err := svc.IssueWIA(IssueWIARequest{ClientID: "wallet-instance-1", JWK: holderJWK})
	if err != nil {
		t.Fatalf("IssueWIA: %v", err)
	}
	if result.WIA == "" {
		t.Fatal("expected a non-empty WIA")
	}
	if result.ExpiresIn != int64((24 * time.Hour).Seconds()) {
		t.Fatalf("expected expires_in=%d, got %d", int64((24 * time.Hour).Seconds()), result.ExpiresIn)
	}

	// Verify the JWS signature and inspect claims/headers.
	msg, err := jws.Parse([]byte(result.WIA))
	if err != nil {
		t.Fatalf("parsing WIA as JWS: %v", err)
	}
	sig := msg.Signatures()[0]
	if got, _ := sig.ProtectedHeaders().Type(); got != WIAType {
		t.Errorf("typ = %q, want %q", got, WIAType)
	}
	if got, _ := sig.ProtectedHeaders().KeyID(); got == "" {
		t.Error("expected a non-empty kid")
	}
	if chain, ok := sig.ProtectedHeaders().X509CertChain(); !ok || chain.Len() == 0 {
		t.Error("expected a non-empty x5c chain")
	}

	token, err := jwt.Parse([]byte(result.WIA), jwt.WithVerify(false))
	if err != nil {
		t.Fatalf("parsing WIA claims: %v", err)
	}
	if iss, _ := token.Issuer(); iss != "https://wallet-attestations.fikua.com" {
		t.Errorf("iss = %q, want the service base URL", iss)
	}
	sub, ok := token.Subject()
	if !ok || sub != "wallet-instance-1" {
		t.Errorf("sub = %q, want %q", sub, "wallet-instance-1")
	}
	var cnf map[string]any
	if err := token.Get("cnf", &cnf); err != nil {
		t.Fatalf("expected a cnf claim: %v", err)
	}
	if _, ok := cnf["jwk"]; !ok {
		t.Error("expected cnf.jwk to be set")
	}
}

func TestIssueWIA_MissingClientID(t *testing.T) {
	svc := NewService("https://wallet-attestations.fikua.com", testSigningKey(t), 24*time.Hour)
	_, err := svc.IssueWIA(IssueWIARequest{JWK: testHolderJWK(t)})
	if err == nil {
		t.Fatal("expected an error for a missing client_id")
	}
}

func TestIssueWIA_MissingJWK(t *testing.T) {
	svc := NewService("https://wallet-attestations.fikua.com", testSigningKey(t), 24*time.Hour)
	_, err := svc.IssueWIA(IssueWIARequest{ClientID: "wallet-instance-1"})
	if err == nil {
		t.Fatal("expected an error for a missing jwk")
	}
}

func TestIssueWIA_InvalidJWK(t *testing.T) {
	svc := NewService("https://wallet-attestations.fikua.com", testSigningKey(t), 24*time.Hour)
	_, err := svc.IssueWIA(IssueWIARequest{ClientID: "wallet-instance-1", JWK: json.RawMessage(`{"not":"a jwk"}`)})
	if err == nil {
		t.Fatal("expected an error for an invalid jwk")
	}
}

func TestStatus(t *testing.T) {
	svc := NewService("https://wallet-attestations.fikua.com", testSigningKey(t), 24*time.Hour)
	status := svc.Status("wallet-instance-1")
	if status.ID != "wallet-instance-1" {
		t.Errorf("ID = %q, want %q", status.ID, "wallet-instance-1")
	}
	if status.Status != "valid" {
		t.Errorf("Status = %q, want %q", status.Status, "valid")
	}
}
