package metrics

import (
	"testing"

	dto "github.com/prometheus/client_model/go"
)

func TestNew(t *testing.T) {
	m := New("v1.0.0")

	if m.HTTPRequestsTotal == nil {
		t.Error("HTTPRequestsTotal is nil")
	}
	if m.HTTPRequestDuration == nil {
		t.Error("HTTPRequestDuration is nil")
	}
	if m.CacheRequestsTotal == nil {
		t.Error("CacheRequestsTotal is nil")
	}
	if m.CacheEntries == nil {
		t.Error("CacheEntries is nil")
	}
	if m.ClusterDegraded == nil {
		t.Error("ClusterDegraded is nil")
	}
	if m.CredentialRenewalTotal == nil {
		t.Error("CredentialRenewalTotal is nil")
	}
	if m.CredentialExpirySeconds == nil {
		t.Error("CredentialExpirySeconds is nil")
	}
	if m.ServerInfo == nil {
		t.Error("ServerInfo is nil")
	}

	// Verify server_info is set to 1 for the given version
	gauge, err := m.ServerInfo.GetMetricWithLabelValues("v1.0.0")
	if err != nil {
		t.Fatalf("failed to get metric: %v", err)
	}
	metric := &dto.Metric{}
	if err := gauge.Write(metric); err != nil {
		t.Fatalf("failed to write metric: %v", err)
	}
	if metric.Gauge.GetValue() != 1 {
		t.Errorf("server_info = %v, want 1", metric.Gauge.GetValue())
	}
}
