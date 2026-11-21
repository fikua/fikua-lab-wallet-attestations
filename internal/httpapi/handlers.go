// Package httpapi exposes this service's endpoints: WIA issuance and its
// (mock) status check.
package httpapi

import (
	"encoding/json"
	"net/http"

	"github.com/fikua/fikua-lab-wallet-attestations/internal/audit"
	"github.com/fikua/fikua-lab-wallet-attestations/internal/health"
	"github.com/fikua/fikua-lab-wallet-attestations/internal/walletprovider"
)

// Handler serves the Wallet Provider's JSON API.
type Handler struct {
	walletProvider *walletprovider.Service
}

// NewHandler builds an httpapi Handler.
func NewHandler(walletProvider *walletprovider.Service) *Handler {
	return &Handler{walletProvider: walletProvider}
}

// Routes registers this handler's endpoints on mux. Paths match the Java
// service's ("/wallet-provider/issue-wia",
// "/wallet-provider/attestation/status") so fikua-lab-wallet needs no
// client-side change beyond its base URL.
func (h *Handler) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /health", h.health)
	mux.HandleFunc("POST /wallet-provider/issue-wia", h.issueWIA)
	mux.HandleFunc("GET /wallet-provider/attestation/status", h.attestationStatus)
}

func (h *Handler) health(w http.ResponseWriter, r *http.Request) {
	health.Handler("", nil)(w, r)
}

func (h *Handler) issueWIA(w http.ResponseWriter, r *http.Request) {
	var req walletprovider.IssueWIARequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		audit.Rejected(r.Context(), "invalid_json")
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json"})
		return
	}

	result, err := h.walletProvider.IssueWIA(req)
	if err != nil {
		audit.Rejected(r.Context(), "invalid_request")
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	audit.WIAIssued(r.Context(), result.KeyThumbprint)
	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) attestationStatus(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing id"})
		return
	}
	writeJSON(w, http.StatusOK, h.walletProvider.Status(id))
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
