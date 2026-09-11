package walletprovider

import (
	"crypto"
	"encoding/base64"

	joseCert "github.com/lestrrat-go/jwx/v3/cert"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// SigningKey is this Wallet Provider's WIA-signing key: a crypto.Signer —
// in every real deployment a cscclient.Signer delegating to the Fikua
// DSS — plus the leaf certificate that goes into the JWS x5c header.
//
// There is deliberately no LoadFromPEM sibling here, unlike
// fikua-lab-idp's access-token SigningKey. The distinction is who checks
// the signature: an access token is verified against a JWK Set this
// ecosystem publishes and controls itself, so a local key is enough
// trust. A WIA is checked by a Credential Issuer deciding whether to
// trust a wallet instance it has never seen before, against this
// certificate's chain — trust that only exists if the private key lives
// in the DSS's HSM behind a real certificate, not in a PEM file next to
// the binary.
type SigningKey struct {
	kid      string
	signer   crypto.Signer
	x5cChain [][]byte // leaf-first DER, trust anchor excluded (HAIP §6.1.1)
}

// NewSigningKey builds a SigningKey from signer and its leaf-first DER
// certificate chain (which must exclude the trust anchor — see
// cscclient.Signer.LeafDER). The kid is the RFC 7638 SHA-256 thumbprint
// of the public key, never a random value, so the same credential always
// presents the same kid across restarts.
func NewSigningKey(signer crypto.Signer, certChainDER [][]byte) (*SigningKey, error) {
	pub, err := jwk.Import(signer.Public())
	if err != nil {
		return nil, err
	}
	thumbprint, err := pub.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, err
	}
	return &SigningKey{
		kid:      base64.RawURLEncoding.EncodeToString(thumbprint),
		signer:   signer,
		x5cChain: certChainDER,
	}, nil
}

// KID returns the key's id — the RFC 7638 SHA-256 JWK thumbprint.
func (k *SigningKey) KID() string {
	return k.kid
}

// Signer returns the crypto.Signer backing this key, for jws.Sign /
// jwt.Sign's WithKey option.
func (k *SigningKey) Signer() crypto.Signer {
	return k.signer
}

// Algorithm is the JWS algorithm WIAs are signed with. ES256 throughout,
// like every other signature in this ecosystem.
func (k *SigningKey) Algorithm() jwa.SignatureAlgorithm {
	return jwa.ES256()
}

// JOSEX5CChain builds this key's chain in the JOSE x5c wire format
// (base64-encoded DER per entry), ready for a jws protected header.
func (k *SigningKey) JOSEX5CChain() (*joseCert.Chain, error) {
	if len(k.x5cChain) == 0 {
		return nil, nil
	}
	var chain joseCert.Chain
	for _, der := range k.x5cChain {
		// cert.Chain.Add expects PEM or a base64-encoded DER string (the
		// JOSE x5c wire format), so raw DER must be encoded first.
		if err := chain.AddString(base64.StdEncoding.EncodeToString(der)); err != nil {
			return nil, err
		}
	}
	return &chain, nil
}
