// Package audit emits the audit events of the Fikua Lab Wallet Provider and
// counts its business operations (Fikua observability convention, OBS-09 and
// OBS-12). The platform Collector archives the events, locked, for five years;
// the catalogue was reviewed on 2026-11-16 (Oriol Canadés):
//
//	event.name     when                                   attributes
//	wia.issued     a Wallet Instance Attestation was signed  wallet.key_thumbprint
//	auth.rejected  an issuance request was refused           reason
//
// wallet.key_thumbprint is the RFC 7638 SHA-256 thumbprint of the wallet's
// proof-of-possession key: it identifies the wallet instance, not a person.
package audit

import (
	"context"
	"sync"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/log/global"
	"go.opentelemetry.io/otel/metric"
)

const (
	scope       = "fikua-lab-wallet-attestations/audit"
	counterName = "wia.business.operations"
)

// WIAIssued records a signed Wallet Instance Attestation.
func WIAIssued(ctx context.Context, keyThumbprint string) {
	Emit(ctx, "wia.issued", attribute.String("wallet.key_thumbprint", keyThumbprint))
	Count(ctx, "wia.issue", "success", "")
}

// Rejected records a refused issuance request.
func Rejected(ctx context.Context, reason string) {
	Emit(ctx, "auth.rejected", attribute.String("reason", reason))
	Count(ctx, "wia.issue", "rejected", reason)
}

// Emit sends one audit event: an OpenTelemetry log record with
// event.domain = audit and the catalogue attributes. It never fails the caller.
func Emit(ctx context.Context, name string, attrs ...attribute.KeyValue) {
	var r log.Record
	r.SetSeverity(log.SeverityInfo)
	r.SetSeverityText("INFO")
	r.SetBody(attribute.StringValue(name))
	r.AddAttributes(attribute.String("event.domain", "audit"), attribute.String("event.name", name))
	r.AddAttributes(attrs...)
	global.GetLoggerProvider().Logger(scope).Emit(ctx, r)
}

var (
	counterOnce sync.Once
	counter     metric.Int64Counter
)

// Count adds one business operation to the service's counter (OBS-09).
// errorType is set only when the operation failed or was refused.
func Count(ctx context.Context, operation, outcome, errorType string) {
	counterOnce.Do(func() {
		counter, _ = otel.GetMeterProvider().Meter(scope).Int64Counter(counterName,
			metric.WithDescription("Business operations, by operation and outcome"),
			metric.WithUnit("{operation}"))
	})
	if counter == nil {
		return
	}
	attrs := []attribute.KeyValue{attribute.String("operation", operation), attribute.String("outcome", outcome)}
	if errorType != "" {
		attrs = append(attrs, attribute.String("error.type", errorType))
	}
	counter.Add(ctx, 1, metric.WithAttributes(attrs...))
}
