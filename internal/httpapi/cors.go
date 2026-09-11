package httpapi

import "net/http"

// WithCORS wraps next with permissive CORS headers — this service is
// called by wallet clients running as web apps from arbitrary origins,
// and issuing a WIA carries no origin-based access control of its own
// (the wallet authenticates itself implicitly by presenting its own PoP
// key, not by browser origin). Restricting Origin here would only block
// legitimate wallets running from a different origin, without adding any
// real access control. See fikua-lab-idp's identical cors.go.
func WithCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
